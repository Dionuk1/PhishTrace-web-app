(function () {
    "use strict";

    var API_KEY = "YOUR_API_KEY";
    var SCAN_ENDPOINT = "https://developers.bolster.ai/api/neo/scan";
    var STATUS_ENDPOINT = "https://developers.bolster.ai/api/neo/scan/status";
    var HISTORY_KEY = "phishtrace_scan_history";
    var MAX_HISTORY = 8;

    var form = document.getElementById("scanForm");
    var input = document.getElementById("urlInput");
    var help = document.getElementById("inputHelp");
    var button = document.getElementById("scanButton");
    var loader = document.getElementById("scanLoader");
    var emptyState = document.getElementById("emptyState");
    var resultContent = document.getElementById("resultContent");
    var resultUrl = document.getElementById("resultUrl");
    var threatBadge = document.getElementById("threatBadge");
    var threatStatus = document.getElementById("threatStatus");
    var confidenceScore = document.getElementById("confidenceScore");
    var scanTime = document.getElementById("scanTime");
    var screenshotPreview = document.getElementById("screenshotPreview");
    var categoryList = document.getElementById("categoryList");
    var historyList = document.getElementById("historyList");
    var clearHistory = document.getElementById("clearHistory");
    var toastStack = document.getElementById("toastStack");

    form.addEventListener("submit", function (event) {
        event.preventDefault();
        scanUrl(input.value.trim());
    });

    input.addEventListener("input", function () {
        input.classList.remove("is-invalid");
        help.textContent = "Enter a complete URL beginning with http:// or https://.";
    });

    clearHistory.addEventListener("click", function () {
        localStorage.removeItem(HISTORY_KEY);
        renderHistory();
        showToast("Local scan history cleared.", "success");
    });

    renderHistory();

    async function scanUrl(rawUrl) {
        var validation = validateUrl(rawUrl);

        if (!validation.valid) {
            input.classList.add("is-invalid");
            help.textContent = validation.message;
            showToast(validation.message, "error");
            return;
        }

        setScanning(true);

        try {
            var startedAt = Date.now();
            var scanResponse = await postJson(SCAN_ENDPOINT, {
                apiKey: API_KEY,
                urlInfo: {
                    url: validation.url
                },
                scanType: "quick"
            });
            var jobId = scanResponse.jobID || scanResponse.jobId || scanResponse.job_id || scanResponse.id;

            if (!jobId) {
                throw new Error("CheckPhish did not return a jobID.");
            }

            showToast("Scan job created. Waiting for results.", "success");
            var result = await pollForResult(jobId);
            var normalized = normalizeResult(result, validation.url, startedAt);

            renderResult(normalized);
            saveHistory(normalized);
            renderHistory();
            showToast("Threat analysis completed.", "success");
        } catch (error) {
            showToast(error.message || "Unable to complete the scan.", "error");
        } finally {
            setScanning(false);
        }
    }

    function validateUrl(value) {
        if (!value) {
            return {
                valid: false,
                message: "Please enter a URL to analyze."
            };
        }

        try {
            var parsed = new URL(value);
            if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
                return {
                    valid: false,
                    message: "URL must begin with http:// or https://."
                };
            }

            return {
                valid: true,
                url: parsed.href
            };
        } catch (error) {
            return {
                valid: false,
                message: "Enter a valid URL, for example https://example.com."
            };
        }
    }

    async function pollForResult(jobId) {
        var lastResult = null;

        for (var attempt = 0; attempt < 18; attempt += 1) {
            await wait(attempt === 0 ? 1600 : 2500);
            lastResult = await postJson(STATUS_ENDPOINT, {
                apiKey: API_KEY,
                jobID: jobId,
                insights: true
            });

            if (isResultReady(lastResult)) {
                return lastResult;
            }
        }

        if (lastResult) {
            return lastResult;
        }

        throw new Error("Scan timed out before results were available.");
    }

    async function postJson(url, body) {
        var response = await fetch(url, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(body)
        });

        var payload = await response.json().catch(function () {
            return {};
        });

        if (!response.ok) {
            throw new Error(payload.message || payload.error || "CheckPhish API request failed.");
        }

        return payload;
    }

    function isResultReady(payload) {
        var status = String(
            payload.status ||
            payload.scanStatus ||
            payload.disposition ||
            payload.data && payload.data.status ||
            ""
        ).toLowerCase();

        return status.indexOf("complete") !== -1 ||
            status.indexOf("done") !== -1 ||
            status.indexOf("finished") !== -1 ||
            Boolean(payload.disposition || payload.verdict || payload.urlInfo || payload.data && payload.data.urlInfo);
    }

    function normalizeResult(payload, submittedUrl, startedAt) {
        var source = payload.data || payload.result || payload;
        var urlInfo = source.urlInfo || source.url_info || {};
        var status = source.disposition || source.verdict || source.status || source.threatStatus || source.category || "Unknown";
        var confidence = source.confidence || source.confidenceScore || source.score || source.riskScore || urlInfo.confidence || null;
        var screenshot = source.screenshot_path || source.screenshotUrl || source.screenshot || source.imageUrl || source.pageScreenshot || urlInfo.screenshot || "";
        var categories = source.categories || source.tags || source.threatTypes || source.classification || urlInfo.categories || [];
        var scanStart = Number(source.scan_start_ts || 0);
        var scanEnd = Number(source.scan_end_ts || 0);

        if (typeof categories === "string") {
            categories = categories.split(",").map(function (item) {
                return item.trim();
            }).filter(Boolean);
        }

        if (!Array.isArray(categories)) {
            categories = ["Uncategorized"];
        }

        categories = categories.map(function (category) {
            if (category && typeof category === "object") {
                if (confidence === null && category.score !== undefined) {
                    confidence = category.score;
                }

                return category.category || category.name || category.type || "Uncategorized";
            }

            return category;
        }).filter(Boolean);

        if (categories.length === 0) {
            categories = ["Uncategorized"];
        }

        return {
            url: urlInfo.url || source.url || submittedUrl,
            status: String(status),
            level: threatLevel(status),
            confidence: formatConfidence(confidence),
            screenshot: screenshot,
            categories: categories,
            scanTime: scanStart && scanEnd ? formatDuration(scanEnd - scanStart) : formatDuration(Date.now() - startedAt),
            scannedAt: new Date().toLocaleString()
        };
    }

    function threatLevel(status) {
        var value = String(status).toLowerCase();

        if (value.indexOf("phish") !== -1 || value.indexOf("scam") !== -1 || value.indexOf("malicious") !== -1 || value.indexOf("unsafe") !== -1 || value.indexOf("danger") !== -1 || value.indexOf("hacked") !== -1 || value.indexOf("cryptojacking") !== -1) {
            return "danger";
        }

        if (value.indexOf("likely") !== -1 || value.indexOf("suspicious") !== -1 || value.indexOf("unknown") !== -1 || value.indexOf("warn") !== -1) {
            return "warning";
        }

        return "safe";
    }

    function formatConfidence(value) {
        if (value === null || value === undefined || value === "") {
            return "N/A";
        }

        var number = Number(value);

        if (Number.isNaN(number)) {
            return String(value);
        }

        if (number <= 1) {
            return Math.round(number * 100) + "%";
        }

        return Math.round(number) + "%";
    }

    function formatDuration(ms) {
        var seconds = Math.max(1, Math.round(ms / 1000));
        return seconds + "s";
    }

    function renderResult(result) {
        emptyState.hidden = true;
        resultContent.hidden = false;

        resultUrl.textContent = result.url;
        threatStatus.textContent = result.status;
        confidenceScore.textContent = result.confidence;
        scanTime.textContent = result.scanTime;

        threatBadge.className = "threat-badge " + result.level;
        threatBadge.textContent = result.level === "danger" ? "High Threat" : result.level === "warning" ? "Suspicious" : "Safe";

        screenshotPreview.innerHTML = "";
        if (result.screenshot) {
            var image = document.createElement("img");
            image.src = result.screenshot;
            image.alt = "Screenshot preview for " + result.url;
            screenshotPreview.appendChild(image);
        } else {
            var fallback = document.createElement("span");
            fallback.textContent = "Screenshot preview unavailable";
            screenshotPreview.appendChild(fallback);
        }

        categoryList.innerHTML = "";
        result.categories.forEach(function (category) {
            var pill = document.createElement("span");
            pill.className = "category-pill";
            pill.textContent = category;
            categoryList.appendChild(pill);
        });
    }

    function saveHistory(result) {
        var history = readHistory().filter(function (item) {
            return item.url !== result.url;
        });

        history.unshift(result);
        localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(0, MAX_HISTORY)));
    }

    function readHistory() {
        try {
            return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
        } catch (error) {
            return [];
        }
    }

    function renderHistory() {
        var history = readHistory();
        historyList.innerHTML = "";

        if (history.length === 0) {
            var empty = document.createElement("p");
            empty.className = "history-empty";
            empty.textContent = "No local scans yet.";
            historyList.appendChild(empty);
            return;
        }

        history.forEach(function (item) {
            var row = document.createElement("button");
            row.type = "button";
            row.className = "history-item";
            row.innerHTML = "<strong></strong><div class=\"history-item-meta\"><span></span><span></span></div>";
            row.querySelector("strong").textContent = item.url;
            row.querySelector(".history-item-meta span:first-child").textContent = item.status;
            row.querySelector(".history-item-meta span:last-child").textContent = item.scannedAt;
            row.addEventListener("click", function () {
                renderResult(item);
            });
            historyList.appendChild(row);
        });
    }

    function setScanning(isScanning) {
        button.disabled = isScanning;
        input.disabled = isScanning;
        loader.hidden = !isScanning;
        button.querySelector(".button-text").textContent = isScanning ? "Scanning" : "Scan Now";
    }

    function showToast(message, type) {
        var toast = document.createElement("div");
        toast.className = "toast " + (type || "");
        toast.textContent = message;
        toastStack.appendChild(toast);

        window.setTimeout(function () {
            toast.remove();
        }, 4200);
    }

    function wait(ms) {
        return new Promise(function (resolve) {
            window.setTimeout(resolve, ms);
        });
    }
}());
