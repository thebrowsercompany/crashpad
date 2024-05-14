// Copyright 2015 The Crashpad Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "handler/crash_report_upload_thread.h"

#include <errno.h>
#include <time.h>

#include <algorithm>
#include <map>
#include <memory>
#include <utility>
#include <vector>

#include "base/logging.h"
#include "base/notreached.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "build/build_config.h"
#include "client/settings.h"
#include "handler/minidump_to_upload_parameters.h"
#include "snapshot/minidump/process_snapshot_minidump.h"
#include "snapshot/module_snapshot.h"
#include "util/file/file_reader.h"
#include "util/misc/metrics.h"
#include "util/misc/uuid.h"
#include "util/net/http_body.h"
#include "util/net/http_multipart_builder.h"
#include "util/net/http_transport.h"
#include "util/net/url.h"
#include "util/stdlib/map_insert.h"

#if BUILDFLAG(IS_APPLE)
#include "handler/mac/file_limit_annotation.h"
#endif  // BUILDFLAG(IS_APPLE)

#if BUILDFLAG(IS_IOS)
#include "util/ios/scoped_background_task.h"
#endif  // BUILDFLAG(IS_IOS)

#if BUILDFLAG(IS_WIN)
#include "../../vendor/mpack.h"  // BCNY_ARC
#endif

namespace crashpad {

namespace {

// The number of seconds to wait between checking for pending reports.
const int kRetryWorkIntervalSeconds = 15 * 60;

#if BUILDFLAG(IS_IOS)
// The number of times to attempt to upload a pending report, repeated on
// failure. Attempts will happen once per launch, once per call to
// ReportPending(), and, if Options.watch_pending_reports is true, once every
// kRetryWorkIntervalSeconds. Currently iOS only.
const int kRetryAttempts = 5;
#endif

// Wraps a reference to a no-args function (which can be empty). When this
// object goes out of scope, invokes the function if it is non-empty.
//
// The lifetime of the function must outlive the lifetime of this object.
class ScopedFunctionInvoker final {
 public:
  ScopedFunctionInvoker(const std::function<void()>& function)
      : function_(function) {}
  ScopedFunctionInvoker(const ScopedFunctionInvoker&) = delete;
  ScopedFunctionInvoker& operator=(const ScopedFunctionInvoker&) = delete;

  ~ScopedFunctionInvoker() {
    if (function_) {
      function_();
    }
  }

 private:
  const std::function<void()>& function_;
};

}  // namespace

CrashReportUploadThread::CrashReportUploadThread(
    CrashReportDatabase* database,
    std::string url,
    std::string http_proxy,
    const Options& options,
    ProcessPendingReportsObservationCallback callback)
    : options_(options),
      callback_(std::move(callback)),
      url_(std::move(url)),
      http_proxy_(std::move(http_proxy)),
      // When watching for pending reports, check every 15 minutes, even in the
      // absence of a signal from the handler thread. This allows for failed
      // uploads to be retried periodically, and for pending reports written by
      // other processes to be recognized.
      thread_(options.watch_pending_reports ? kRetryWorkIntervalSeconds
                                            : WorkerThread::kIndefiniteWait,
              this),
      known_pending_report_uuids_(),
      database_(database) {
  DCHECK(!url_.empty());
}

CrashReportUploadThread::~CrashReportUploadThread() {
}

void CrashReportUploadThread::ReportPending(const UUID& report_uuid) {
  known_pending_report_uuids_.PushBack(report_uuid);
  if (thread_.is_running())
    thread_.DoWorkNow();
}

void CrashReportUploadThread::Start() {
  thread_.Start(
      options_.watch_pending_reports ? 0.0 : WorkerThread::kIndefiniteWait);
}

void CrashReportUploadThread::Stop() {
  thread_.Stop();
}

void CrashReportUploadThread::ProcessPendingReports() {
#if BUILDFLAG(IS_IOS)
  internal::ScopedBackgroundTask scoper("CrashReportUploadThread");
#endif  // BUILDFLAG(IS_IOS)

  // If callback_ is non-empty, invoke it when this function returns after
  // uploads complete (regardless of whether or not that succeeded).
  ScopedFunctionInvoker scoped_function_invoker(callback_);

  std::vector<UUID> known_report_uuids = known_pending_report_uuids_.Drain();
  for (const UUID& report_uuid : known_report_uuids) {
    CrashReportDatabase::Report report;
    if (database_->LookUpCrashReport(report_uuid, &report) !=
        CrashReportDatabase::kNoError) {
      continue;
    }

    ProcessPendingReport(report);

    // Respect Stop() being called after at least one attempt to process a
    // report.
    if (!thread_.is_running()) {
      return;
    }
  }

  // Known pending reports are always processed (above). The rest of this
  // function is concerned with scanning for pending reports not already known
  // to this thread.
  if (!options_.watch_pending_reports) {
    return;
  }

  std::vector<CrashReportDatabase::Report> reports;
  if (database_->GetPendingReports(&reports) != CrashReportDatabase::kNoError) {
    // The database is sick. It might be prudent to stop trying to poke it from
    // this thread by abandoning the thread altogether. On the other hand, if
    // the problem is transient, it might be possible to talk to it again on the
    // next pass. For now, take the latter approach.
    return;
  }

  for (const CrashReportDatabase::Report& report : reports) {
    if (std::find(known_report_uuids.begin(),
                  known_report_uuids.end(),
                  report.uuid) != known_report_uuids.end()) {
      // An attempt to process the report already occurred above. The report is
      // still pending, so upload must have failed. Don’t retry it immediately,
      // it can wait until at least the next pass through this method.
      continue;
    }

    ProcessPendingReport(report);

    // Respect Stop() being called after at least one attempt to process a
    // report.
    if (!thread_.is_running()) {
      return;
    }
  }
}

void CrashReportUploadThread::ProcessPendingReport(
    const CrashReportDatabase::Report& report) {
#if BUILDFLAG(IS_APPLE)
  RecordFileLimitAnnotation();
#endif  // BUILDFLAG(IS_APPLE)

  Settings* const settings = database_->GetSettings();

  bool uploads_enabled;
  if (!report.upload_explicitly_requested &&
      (!settings->GetUploadsEnabled(&uploads_enabled) || !uploads_enabled)) {
    // Don’t attempt an upload if there’s no URL to upload to. Allow upload if
    // it has been explicitly requested by the user, otherwise, respect the
    // upload-enabled state stored in the database’s settings.
    database_->SkipReportUpload(report.uuid,
                                Metrics::CrashSkippedReason::kUploadsDisabled);
    return;
  }

  if (ShouldRateLimitUpload(report))
    return;

#if BUILDFLAG(IS_IOS)
  if (ShouldRateLimitRetry(report))
    return;
#endif  // BUILDFLAG(IS_IOS)

  std::unique_ptr<const CrashReportDatabase::UploadReport> upload_report;
  CrashReportDatabase::OperationStatus status =
      database_->GetReportForUploading(report.uuid, &upload_report);
  switch (status) {
    case CrashReportDatabase::kNoError:
      break;

    case CrashReportDatabase::kBusyError:
    case CrashReportDatabase::kReportNotFound:
      // Someone else may have gotten to it first. If they’re working on it now,
      // this will be kBusyError. If they’ve already finished with it, it’ll be
      // kReportNotFound.
      return;

    case CrashReportDatabase::kFileSystemError:
    case CrashReportDatabase::kDatabaseError:
      // In these cases, SkipReportUpload() might not work either, but it’s best
      // to at least try to get the report out of the way.
      database_->SkipReportUpload(report.uuid,
                                  Metrics::CrashSkippedReason::kDatabaseError);
      return;

    case CrashReportDatabase::kCannotRequestUpload:
      NOTREACHED();
      return;
  }

  std::string response_body;
  UploadResult upload_result =
      UploadReport(upload_report.get(), &response_body);
  switch (upload_result) {
    case UploadResult::kSuccess:
      database_->RecordUploadComplete(std::move(upload_report), response_body);
      break;
    case UploadResult::kPermanentFailure:
      upload_report.reset();
      database_->SkipReportUpload(
          report.uuid, Metrics::CrashSkippedReason::kPrepareForUploadFailed);
      break;
    case UploadResult::kRetry:
#if BUILDFLAG(IS_IOS)
      if (upload_report->upload_attempts > kRetryAttempts) {
        upload_report.reset();
        database_->SkipReportUpload(report.uuid,
                                    Metrics::CrashSkippedReason::kUploadFailed);
      } else {
        Metrics::CrashUploadSkipped(
            Metrics::CrashSkippedReason::kUploadFailedButCanRetry);
        retry_uuid_time_map_[report.uuid] =
            time(nullptr) +
            (1 << upload_report->upload_attempts) * kRetryWorkIntervalSeconds;
      }
#else
      upload_report.reset();

      // TODO(mark): Deal with retries properly: don’t call SkipReportUplaod()
      // if the result was kRetry and the report hasn’t already been retried
      // too many times.
      database_->SkipReportUpload(report.uuid,
                                  Metrics::CrashSkippedReason::kUploadFailed);
#endif
      break;
  }
}

// START BCNY_ARC
static bool ReadEntireFile(FileReader* reader, std::string* contents) {
  char buffer[4096];
  std::string local_contents;
  FileOperationResult rv;
  while ((rv = reader->Read(buffer, sizeof(buffer))) > 0) {
    local_contents.append(buffer, rv);
  }
  if (rv < 0) {
    return false;
  }
  contents->swap(local_contents);
  return true;
}

static void AppendStringJsonQuoted(std::string* into,
                                   const char* data,
                                   size_t len) {
  into->append("\"");
  for (size_t i = 0; i < len; ++i) {
    char c = data[i];
    if (c < ' ' || c == '"' || c  == '\\') {
      char buf[10];
      // Since this isn't for human consumption, no need for \\n-style.
      snprintf(buf, sizeof(buf), "\\u%04x", c);
      into->append(buf);
      continue;
    }
    into->append(1, c);
  }
  into->append("\"");
}

// This a conversion from mpack node trees to JSON as string. Specific fields
// are overridden while constructing the final JSON string, in particular:
// 1) at the root, "level" is overridden to "error" (rather than "fatal")
// 2) inside the "tags" dict found at the root, a "process_type" entry is added
//    corresponding to |ptype|.
static bool ToJsonWithOverrides(mpack_node_t node,
                                const std::string& ptype,
                                const std::vector<std::string>& path_to_here,
                                std::string* into) {
  DCHECK(ptype != "");
  switch (mpack_node_tag(node).type) {
    case mpack_type_nil:
      into->append("null");
      return true;
    case mpack_type_bool:
      into->append(mpack_node_bool(node)? "true":"false");
      return true;
    case mpack_type_int: {
      // See sentry__jsonwriter_write_int32().
      char buf[16];
      snprintf(buf, sizeof(buf), "%" PRId32, mpack_node_i32(node));
      into->append(buf);
      return true;
    }
    case mpack_type_double: {
      // See sentry__jsonwriter_write_double().
      char buf[24];
      double val = mpack_node_double(node);
      int written = snprintf(buf, sizeof(buf), "%.16g", val);
      if (written < 0 || written >= (int)sizeof(buf) || !isfinite(val)) {
        into->append("null");
      } else {
        buf[written] = '\0';
        into->append(buf);
      }
      return true;
    }
    case mpack_type_str: {
      if (path_to_here.size() == 1 &&
          path_to_here[0] == "level") {
        // Override: Any child process, mark as non-fatal.
        static const char kError[] = "error";
        AppendStringJsonQuoted(into, kError, strlen(kError));
      } else {
        AppendStringJsonQuoted(into, mpack_node_str(node), mpack_node_strlen(node));
      }
      return true;
                         }
    case mpack_type_array: {
      into->append("[");
      for (size_t i = 0; i < mpack_node_array_length(node); ++i) {
        mpack_node_t elem = mpack_node_array_at(node, i);

        std::vector<std::string> new_path = path_to_here;
        char buf[16];
        snprintf(buf, sizeof(buf), ".%llu", i);
        new_path.push_back(buf);
        ToJsonWithOverrides(elem, ptype, new_path, into);

        if (i < mpack_node_array_length(node) - 1) {
          into->append(",");
        }
      }
      into->append("]");
      return true;
    }
    case mpack_type_map: {
      into->append("{");
      for (size_t i = 0; i < mpack_node_map_count(node); ++i) {
        mpack_node_t key = mpack_node_map_key_at(node, i);
        mpack_node_t value = mpack_node_map_value_at(node, i);

        AppendStringJsonQuoted(
            into, mpack_node_str(key), mpack_node_strlen(key));
        into->append(":");

        std::vector<std::string> new_path = path_to_here;
        new_path.push_back(
            std::string(mpack_node_str(key), mpack_node_strlen(key)));
        ToJsonWithOverrides(value, ptype, new_path, into);

        if (i < mpack_node_map_count(node) - 1) {
          into->append(",");
        }
      }

      // Override: Any child process, append ptype as a tag.
      if (path_to_here.size() == 1 &&
          path_to_here[0] == "tags") {
        if (mpack_node_map_count(node) > 0) {
          into->append(",");
        }
        into->append("\"process_type\":");
        AppendStringJsonQuoted(into, ptype.data(), ptype.size());
      }

      into->append("}");
      return true;
    }

    default:
      // There are other msgpack types, but they are not written by Sentry.
      NOTREACHED();
      return false;
  }
}

// sentry-native only supports a single set of tags, which previously are
// applied to browser crashes. Sentry's "event" data is written to a msgpack-d
// file, which is then attached by Crashpad to the minidump upload. This event
// data is treated as the entire set of event tags, and additional form-data
// additions during the HTTP POST are ignored, so we are unable to add fields.
// In particular, we cannot set a tag that indicates that this is the crash of a
// child process. To work around this, rather than just attaching the file
// directly, we load it, add the the special keys required for child processes
// where necessary, and then attach the event data as json form-data rather a
// file attachment.
static bool HandleEventAttachment(HTTPMultipartBuilder& http_multipart_builder,
                                  const std::string& ptype,
                                  FileReader* reader) {
  DCHECK(ptype != "");

  // Start by loading and deserializing the __sentry-event file.
  std::string event_file_contents;
  if (!ReadEntireFile(reader, &event_file_contents)) {
    return false;
  }

  mpack_tree_t tree;
  mpack_tree_init_data(
      &tree, event_file_contents.data(), event_file_contents.size());
  mpack_tree_parse(&tree);
  mpack_node_t root = mpack_tree_root(&tree);

  // Convert the tree to JSON, updating child process fields as we go.
  std::string as_json;
  if (!ToJsonWithOverrides(root, ptype, std::vector<std::string>(), &as_json)) {
    return false;
  }

  if (mpack_tree_destroy(&tree) != mpack_ok) {
    return false;
  }

  // Attach the full (modified) sentry data to the http request.
  http_multipart_builder.SetFormData("sentry", as_json);

  return true;
}
// END BCNY_ARC

CrashReportUploadThread::UploadResult CrashReportUploadThread::UploadReport(
    const CrashReportDatabase::UploadReport* report,
    std::string* response_body) {
  std::map<std::string, std::string> parameters;

  FileReader* reader = report->Reader();
  FileOffset start_offset = reader->SeekGet();
  if (start_offset < 0) {
    return UploadResult::kPermanentFailure;
  }

  // Ignore any errors that might occur when attempting to interpret the
  // minidump file. This may result in its being uploaded with few or no
  // parameters, but as long as there’s a dump file, the server can decide what
  // to do with it.
  ProcessSnapshotMinidump minidump_process_snapshot;
  if (minidump_process_snapshot.Initialize(reader)) {
    parameters =
        BreakpadHTTPFormParametersFromMinidump(&minidump_process_snapshot);
  }

  if (!reader->SeekSet(start_offset)) {
    return UploadResult::kPermanentFailure;
  }

  HTTPMultipartBuilder http_multipart_builder;
  http_multipart_builder.SetGzipEnabled(options_.upload_gzip);

  static constexpr char kMinidumpKey[] = "upload_file_minidump";

  for (const auto& kv : parameters) {
    if (kv.first == kMinidumpKey) {
      LOG(WARNING) << "reserved key " << kv.first << ", discarding value "
                   << kv.second;
    } else {
      http_multipart_builder.SetFormData(kv.first, kv.second);
    }
  }

  bool attachments_handled = false;

  const auto ptype_it = parameters.find("ptype");
  if (ptype_it != parameters.end()) {
    // This is a child process:
    // 1) Modify the Sentry event attachment to update tags for the child
    //    process.
    // 2) Don't attach the other attachments (breadcrumbs) as that causes the
    //    Sentry server to ignore the event data we pass here.
    for (const auto& it : report->GetAttachments()) {
      if (it.first == "__sentry-event") {
        if (HandleEventAttachment(
                http_multipart_builder, ptype_it->second, it.second)) {
          attachments_handled = true;
          break;
        }
      }
    }
  }

  // If this is the browser, or if we failed to update the tags for child due to
  // a failure to load/parse the msgpack, then attach as normal. It will look
  // like a browser crash in that case, but might give us a clue to investigate.
  if (!attachments_handled) {
    for (const auto& it : report->GetAttachments()) {
      http_multipart_builder.SetFileAttachment(
          it.first, it.first, it.second, "application/octet-stream");
    }
  }

  http_multipart_builder.SetFileAttachment(kMinidumpKey,
                                           report->uuid.ToString() + ".dmp",
                                           reader,
                                           "application/octet-stream");

  std::unique_ptr<HTTPTransport> http_transport(HTTPTransport::Create());
  if (!http_transport) {
    return UploadResult::kPermanentFailure;
  }

  HTTPHeaders content_headers;
  http_multipart_builder.PopulateContentHeaders(&content_headers);
  for (const auto& content_header : content_headers) {
    http_transport->SetHeader(content_header.first, content_header.second);
  }
  http_transport->SetBodyStream(http_multipart_builder.GetBodyStream());
  // TODO(mark): The timeout should be configurable by the client.
  http_transport->SetTimeout(internal::kUploadReportTimeoutSeconds);

  std::string url = url_;
  if (options_.identify_client_via_url) {
    // Add parameters to the URL which identify the client to the server.
    static constexpr struct {
      const char* key;
      const char* url_field_name;
    } kURLParameterMappings[] = {
        {"prod", "product"},
        {"ver", "version"},
        {"guid", "guid"},
    };

    for (const auto& parameter_mapping : kURLParameterMappings) {
      const auto it = parameters.find(parameter_mapping.key);
      if (it != parameters.end()) {
        url.append(
            base::StringPrintf("%c%s=%s",
                               url.find('?') == std::string::npos ? '?' : '&',
                               parameter_mapping.url_field_name,
                               URLEncode(it->second).c_str()));
      }
    }
  }
  http_transport->SetURL(url);
  http_transport->SetHTTPProxy(http_proxy_);

  if (!http_transport->ExecuteSynchronously(response_body)) {
    return UploadResult::kRetry;
  }

  return UploadResult::kSuccess;
}

void CrashReportUploadThread::DoWork(const WorkerThread* thread) {
  ProcessPendingReports();
}

bool CrashReportUploadThread::ShouldRateLimitUpload(
    const CrashReportDatabase::Report& report) {
  if (report.upload_explicitly_requested || !options_.rate_limit)
    return false;

  Settings* const settings = database_->GetSettings();
  time_t last_upload_attempt_time;
  if (settings->GetLastUploadAttemptTime(&last_upload_attempt_time)) {
    time_t now = time(nullptr);
    if (now >= last_upload_attempt_time) {
      // If the most recent upload attempt occurred within the past hour,
      // don’t attempt to upload the new report. If it happened longer ago,
      // attempt to upload the report.
      constexpr int kUploadAttemptIntervalSeconds = 60 * 60;  // 1 hour
      if (now - last_upload_attempt_time < kUploadAttemptIntervalSeconds) {
        database_->SkipReportUpload(
            report.uuid, Metrics::CrashSkippedReason::kUploadThrottled);
        return true;
      }
    } else {
      // The most recent upload attempt purportedly occurred in the future. If
      // it “happened” at least one day in the future, assume that the last
      // upload attempt time is bogus, and attempt to upload the report. If
      // the most recent upload time is in the future but within one day,
      // accept it and don’t attempt to upload the report.
      constexpr int kBackwardsClockTolerance = 60 * 60 * 24;  // 1 day
      if (last_upload_attempt_time - now < kBackwardsClockTolerance) {
        database_->SkipReportUpload(
            report.uuid, Metrics::CrashSkippedReason::kUnexpectedTime);
        return true;
      }
    }
  }
  return false;
}

#if BUILDFLAG(IS_IOS)
bool CrashReportUploadThread::ShouldRateLimitRetry(
    const CrashReportDatabase::Report& report) {
  if (retry_uuid_time_map_.find(report.uuid) != retry_uuid_time_map_.end()) {
    time_t now = time(nullptr);
    if (now < retry_uuid_time_map_[report.uuid]) {
      return true;
    } else {
      retry_uuid_time_map_.erase(report.uuid);
    }
  }
  return false;
}
#endif

}  // namespace crashpad
