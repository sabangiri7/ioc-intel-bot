# FortiSIEM Integration Guide

This document covers how to ingest IOC feed data from IOC Intel Bot into FortiSIEM.

## Overview

FortiSIEM ingests external threat intelligence via:

1. **HTTP Workers** — scheduled HTTP jobs that fetch indicators and create events
2. **Reference Collections** — curated sets of IOCs for correlation
3. **Custom Collectors (Java/Python)** — programmatic ingestion via the Collector SDK or REST API

The IOC bot exposes a pull API at `/api/v1/feed` (JSON, CSV, STIX) and supports
outbound push via `config/push.yaml`. Choose the approach that matches your
FortiSIEM version and network topology.

---

## Option A: HTTP Worker (Simplest — no code)

FortiSIEM's built-in HTTP worker can poll the feed on a schedule.

### 1. Create an API key

```bash
# From the IOC bot dashboard or CLI
python3 -m iocbot.keys create fortisiem-worker --scopes read --platform FortiSIEM
```

Or create one via the API (admin scope required):
```bash
curl -X POST "http://iocbot-host/api/v1/keys" \
  -H "X-API-Key: <admin-key>" \
  -H "Content-Type: application/json" \
  -d '{"name":"fortisiem-worker","scopes":"read","platform":"FortiSIEM"}'
```

### 2. Configure the HTTP Worker

In FortiSIEM Supervisor → **Supervisor → Collector/Agent Mgmt → HTTP Workers**:

- **Name**: `IOC-Intel-Bot-Feed`
- **URL**: `http://iocbot-host:8080/api/v1/feed?format=json&min_severity=MEDIUM&view=importable`
- **Headers**: `X-API-Key: iok_...`
- **Method**: `GET`
- **Schedule**: every 4 hours (or as desired)
- **Worker Type**: `Extract and Parse`

### 3. Map Attributes

In the HTTP worker parser, map JSON fields to FortiSIEM attributes:

| JSON Field | FortiSIEM Attribute | Event Type |
|---|---|---|
| `ioc` | `threatFeedValue` | `threatfeed` |
| `ioc_type` | `threatFeedType` | `threatfeed` |
| `severity` | `threatSeverity` | `threatfeed` |
| `categories` | `threatCategory` | `threatfeed` |
| `malware_family` | `threatMalwareFamily` | `threatfeed` |
| `threat_actor` | `threatActor` | `threatfeed` |
| `first_seen` | `threatFirstSeen` | `threatfeed` |
| `last_seen` | `threatLastSeen` | `threatfeed` |

---

## Option B: Reference Collections

For smaller, curated IOC sets, load them into a FortiSIEM reference collection.

### 1. Export IOCs

```bash
curl -H "X-API-Key: iok_..." \
  "http://iocbot-host:8080/api/v1/feed?format=csv&view=importable&min_severity=HIGH" \
  --output iocs.csv
```

### 2. Import into FortiSIEM

FortiSIEM Supervisor → **Threat Intelligence → Reference Collections**:

1. **Create New Collection** → type `IP Address` (or `Domain Name`, `Hash`, etc.)
2. **Import** the CSV file
3. Set **Auto-refresh** to pull from the API URL periodically
4. Use the collection in **Analytics / Correlation Rules**

---

## Option C: Custom Collector (Java Plugin)

For advanced use cases (custom filtering, enrichment, real-time push), build a
Java collector using the FortiSIEM Collector SDK.

### Prerequisites

- FortiSIEM Collector SDK JARs (included with FortiSIEM Collector install)
- JDK 11+
- Maven or Gradle

### Project Structure

```
fortisiem-collector/
├── pom.xml
└── src/
    └── main/
        └── java/
            └── com/example/
                └── IocBotCollector.java
```

### pom.xml

```xml
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>fortisiem-ioc-collector</artifactId>
  <version>1.0.0</version>

  <dependencies>
    <dependency>
      <groupId>com.fortinet.fortisiem</groupId>
      <artifactId>collector-sdk</artifactId>
      <version>7.x.x</version>
      <scope>system</scope>
      <systemPath>/opt/fortinet/fortisiem/collector/lib/collector-sdk.jar</systemPath>
    </dependency>
  </dependencies>

  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-shade-plugin</artifactId>
        <executions>
          <execution>
            <phase>package</phase>
            <goals><goal>shade</goal></goals>
          </execution>
        </executions>
      </plugin>
    </plugins>
  </build>
</project>
```

### IocBotCollector.java

```java
package com.example;

import com.sunnyvale.collector.api.*;
import java.net.*;
import java.io.*;
import org.json.JSONObject;
import org.json.JSONArray;

public class IocBotCollector extends BaseCollector {

    private static final String API_URL = "http://iocbot-host:8080/api/v1/feed?format=json&view=importable";
    private static final String API_KEY = "iok_your_api_key_here";

    @Override
    public void start() throws CollectorException {
        log("Starting IOC Intel Bot collector...");
        schedule(this::pollFeed, 0, 1440); // poll every 24 hours
    }

    @Override
    public void pollFeed() throws CollectorException {
        try {
            URL url = new URL(API_URL);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("X-API-Key", API_KEY);
            conn.setRequestProperty("Accept", "application/json");

            int status = conn.getResponseCode();
            if (status != 200) {
                throw new CollectorException("HTTP " + status + ": " + conn.getResponseMessage());
            }

            BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line);
            }
            br.close();

            JSONObject response = new JSONObject(sb.toString());
            JSONArray items = response.getJSONArray("items");

            for (int i = 0; i < items.length(); i++) {
                JSONObject item = items.getJSONObject(i);
                Event event = new Event();
                event.setEventType("threatfeed");
                event.setAttribute("threatFeedValue", item.getString("ioc"));
                event.setAttribute("threatFeedType", item.getString("ioc_type"));
                event.setAttribute("threatSeverity", item.getString("severity"));
                event.setAttribute("threatMalwareFamily", item.optString("malware_family", ""));
                event.setAttribute("threatActor", item.optString("threat_actor", ""));
                event.setAttribute("threatFirstSeen", item.optString("first_seen", ""));
                event.setAttribute("threatLastSeen", item.optString("last_seen", ""));

                // Map categories
                JSONArray categories = item.optJSONArray("categories");
                if (categories != null && categories.length() > 0) {
                    StringBuilder cat = new StringBuilder();
                    for (int j = 0; j < categories.length(); j++) {
                        if (j > 0) cat.append(",");
                        cat.append(categories.getString(j));
                    }
                    event.setAttribute("threatCategory", cat.toString());
                }

                sendEvent(event);
            }

            log("Collected " + items.length() + " IOCs");

        } catch (Exception e) {
            throw new CollectorException("Failed to poll IOC feed: " + e.getMessage(), e);
        }
    }

    @Override
    public void stop() {
        log("Stopping IOC Intel Bot collector...");
    }
}
```

### Build and Deploy

```bash
# Build the collector JAR
mvn package

# Copy to FortiSIEM collector
scp target/fortisiem-ioc-collector-1.0.0.jar \
  sup1:/opt/fortinet/fortisiem/collector/custom/

# Restart collector service
ssh sup1 "systemctl restart collector"
```

### Configuration in FortiSIEM

1. **Supervisor → Collector/Agent Mgmt → Collectors**
2. Find your collector → **Config** → add:
   ```json
   {
     "api_url": "http://iocbot-host:8080/api/v1/feed",
     "api_key": "iok_...",
     "format": "json",
     "interval_hours": 24
   }
   ```

---

## Option D: Python Scripted Collector

For simpler environments, a Python script on the FortiSIEM supervisor can
poll and push events via the REST API.

```python
#!/usr/bin/env python3
"""Poll IOC bot feed and push to FortiSIEM via REST API."""

import json
import requests
from datetime import datetime

API_URL = "http://iocbot-host:8080/api/v1/feed"
API_KEY = "iok_your_key"
FORTISIEM_URL = "https://fortisiem-supervisor/api/v1/events"
FORTISIEM_USER = "admin"
FORTISIEM_PASS = "password"

headers = {
    "X-API-Key": API_KEY,
    "Content-Type": "application/json",
}

def poll_iocs():
    resp = requests.get(
        API_URL,
        headers=headers,
        params={"format": "json", "view": "importable", "min_severity": "MEDIUM"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["items"]

def push_to_fortisiem(events):
    payload = {
        "events": [
            {
                "eventType": "threatfeed",
                "attributes": {
                    "threatFeedValue": e["ioc"],
                    "threatFeedType": e["ioc_type"],
                    "threatSeverity": e.get("severity", ""),
                    "threatMalwareFamily": e.get("malware_family", ""),
                    "threatActor": e.get("threat_actor", ""),
                    "threatFirstSeen": e.get("first_seen", ""),
                    "threatLastSeen": e.get("last_seen", ""),
                    "threatCategory": ",".join(e.get("categories", [])),
                },
            }
            for e in events
        ]
    }

    resp = requests.post(
        FORTISIEM_URL,
        json=payload,
        auth=(FORTISIEM_USER, FORTISIEM_PASS),
        verify=False,
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json()

if __name__ == "__main__":
    items = poll_iocs()
    print(f"Polled {len(items)} IOCs")
    result = push_to_fortisiem(items)
    print(json.dumps(result, indent=2))
```

Schedule with cron:
```bash
# Run every 6 hours
0 */6 * * * /usr/bin/python3 /opt/scripts/iocbot_poll.py >> /var/log/iocbot_poll.log 2>&1
```

---

## Option E: Outbound Push (If FortiSIEM Exposes a Webhook)

If FortiSIEM can accept webhook callbacks (e.g., via a proxy or custom endpoint),
configure `config/push.yaml`:

```yaml
enabled: true
min_severity: HIGH
view: importable
batch_limit: 5000

targets:
  - name: fortisiem-webhook
    type: webhook
    url: https://fortisiem.example.com/api/threat-intel/webhook
    headers:
      Authorization: Bearer CHANGE_ME_FORTISIEM_TOKEN
    verify_tls: true
```

Then trigger manually or let the GitHub Actions workflow handle it.

---

## Event Schema Mapping

FortiSIEM threat feed events use these standard attributes:

| Attribute | Type | Description |
|---|---|---|
| `threatFeedValue` | string | The IOC value (IP, domain, hash, URL) |
| `threatFeedType` | string | IOC type: IPv4, Domain, SHA256, etc. |
| `threatSeverity` | string | CRITICAL, HIGH, MEDIUM, LOW |
| `threatCategory` | string | Comma-separated categories (C2, MALWARE, etc.) |
| `threatMalwareFamily` | string | Malware family name |
| `threatActor` | string | Threat actor name |
| `threatFirstSeen` | string | ISO date of first appearance |
| `threatLastSeen` | string | ISO date of last appearance |
| `threatSource` | string | Source of the intelligence |

---

## Troubleshooting

### Collector not connecting

1. Verify network connectivity: `curl -H "X-API-Key: ..." http://iocbot-host:8080/api/v1/health`
2. Check API key is valid and has `read` scope
3. Verify TLS settings if using HTTPS

### Events not appearing in FortiSIEM

1. Check collector logs: `/opt/fortinet/fortisiem/collector/logs/`
2. Verify event type mapping (`threatfeed`)
3. Confirm attribute names match FortiSIEM schema
4. Check correlation rules are enabled for threat feed events

### Rate limiting

If polling frequently, add pagination:
```bash
# Only get new/changed IOCs since last check
curl -H "X-API-Key: ..." \
  "http://iocbot-host:8080/api/v1/feed?format=json&since=2026-10-01T00:00:00Z"
```

---

## Related Documentation

- [API Reference](./API.md) — full endpoint documentation
- [Push Configuration](../config/push.yaml) — outbound push setup
- [Architecture](./ARCHITECTURE.md) — system overview
