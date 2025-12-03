#!/usr/bin/env python3
"""
NPM3Guard v2.3 - Enhanced Enterprise Vulnerability Scanner with Enhanced Slack Alerts
===================================================================================
An advanced NPM package vulnerability scanner for VAPT teams with comprehensive Slack reporting
Author: Apnisec
Version: 2.3.0 - Enhanced Slack alerts with detailed vulnerability reporting
"""

import requests
import csv
import os
import json
import argparse
import time
import logging
import csv
from pathlib import Path
import getpass
from io import StringIO
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import base64
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import sqlite3
import hashlib
import re
from dataclasses import dataclass, asdict
from urllib.parse import urlparse

# Enhanced imports for enterprise features
try:
    from semantic_version import Version, NpmSpec
except ImportError:
    print("[!] Please install semantic_version: pip install semantic_version")
    exit(1)

# ------------------ Tool Banner ------------------
TOOL_NAME = r"""
███    ██ ██████  ███    ███ ██████   ██████  ██    ██  █████  ██████  ██████  
████   ██ ██   ██ ████  ████      ██ ██       ██    ██ ██   ██ ██   ██ ██   ██ 
██ ██  ██ ██████  ██ ████ ██  █████  ██   ███ ██    ██ ███████ ██████  ██   ██ 
██  ██ ██ ██      ██  ██  ██      ██ ██    ██ ██    ██ ██   ██ ██   ██ ██   ██ 
██   ████ ██      ██      ██ ██████   ██████   ██████  ██   ██ ██   ██ ██████  

                ▂▃▅▇█▓▒░ Enterprise VAPT Edition v2.3 - Enhanced Slack Alerts ░▒▓█▇▅▃▂
                                   
"""

# ------------------ Enhanced Configuration ------------------
@dataclass
class ScanConfig:
    """Configuration class for scan parameters"""
    rate_limit_delay: float = 1.0
    max_workers: int = 10
    timeout: int = 30
    retries: int = 3
    save_reports: bool = True
    report_format: str = "json"  # json, csv, html
    enable_logging: bool = True
    log_level: str = "INFO"
    custom_vuln_db: Optional[str] = None
    whitelist_packages: List[str] = None
    slack_webhook: Optional[str] = None
    teams_webhook: Optional[str] = None
    recursive_scan: bool = True  # Enable recursive scanning
    detailed_slack_alerts: bool = True  # Enable detailed Slack alerts

# ------------------ Enhanced Vulnerability Database ------------------
class VulnerabilityDatabase:
    """Enhanced vulnerability database with real-time updates"""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.db_path = Path("vuln_database.db")
        self.init_database()
        self.load_vulnerabilities()

    def init_database(self):
        """Initialize SQLite database for vulnerability storage"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY,
                package_name TEXT NOT NULL,
                version_range TEXT NOT NULL,
                severity TEXT NOT NULL,
                cve_id TEXT,
                description TEXT,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source TEXT DEFAULT 'builtin'
            )
            """
        )
        conn.commit()
        conn.close()

    def load_vulnerabilities(self):
        """Load vulnerabilities from database and external sources"""
        self.vulnerabilities: Dict[str, List[Dict]] = {}

        # Load from database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT package_name, version_range, severity, cve_id, description FROM vulnerabilities"
        )

        for package_name, version_range, severity, cve_id, description in cursor.fetchall():
            if package_name not in self.vulnerabilities:
                self.vulnerabilities[package_name] = []

            self.vulnerabilities[package_name].append(
                {
                    "range": version_range,
                    "severity": severity,
                    "cve_id": cve_id,
                    "description": description,
                }
            )

        conn.close()

        # If DB is empty, load built-in vulns (CVE set + shai-hulud-2)
        if not self.vulnerabilities:
            self._load_builtin_vulnerabilities()

    def _load_shai_hulud_malicious_packages(self, builtin_vulns: Dict[str, List[Dict]]):
        """
        Load malicious packages from the shai-hulud-2 campaign list.

        All packages are marked as HIGH severity and will be treated as
        vulnerabilities even if there is no CVE ID.
        """
        SHAI_HULUD_CSV = """Package,Version
02-echo,= 0.0.7
@accordproject/concerto-analysis,= 3.24.1
@accordproject/concerto-linter,= 3.24.1
@accordproject/concerto-linter-default-ruleset,= 3.24.1
@accordproject/concerto-metamodel,= 3.12.5
@accordproject/concerto-types,= 3.24.1
@accordproject/markdown-it-cicero,= 0.16.26
@accordproject/template-engine,= 2.7.2
@actbase/css-to-react-native-transform,= 1.0.3
@actbase/native,= 0.1.32
@actbase/node-server,= 1.1.19
@actbase/react-absolute,= 0.8.3
@actbase/react-daum-postcode,= 1.0.5
@actbase/react-kakaosdk,= 0.9.27
@actbase/react-native-actionsheet,= 1.0.3
@actbase/react-native-devtools,= 0.1.3
@actbase/react-native-fast-image,= 8.5.13
@actbase/react-native-kakao-channel,= 1.0.2
@actbase/react-native-kakao-navi,= 2.0.4
@actbase/react-native-less-transformer,= 1.0.6
@actbase/react-native-naver-login,= 1.0.1
@actbase/react-native-simple-video,= 1.0.13
@actbase/react-native-tiktok,= 1.1.3
@afetcan/api,= 0.0.13
@afetcan/storage,= 0.0.27
@alaan/s2s-auth,= 2.0.3
@alexadark/amadeus-api,= 1.0.4
@alexadark/gatsby-theme-events,= 1.0.1
@alexadark/gatsby-theme-wordpress-blog,= 2.0.1
@alexadark/reusable-functions,= 1.5.1
@alexcolls/nuxt-socket.io,= 0.0.7 || = 0.0.8
@alexcolls/nuxt-ux,= 0.6.1 || = 0.6.2
@antstackio/eslint-config-antstack,= 0.0.3
@antstackio/express-graphql-proxy,= 0.2.8
@antstackio/graphql-body-parser,= 0.1.1
@antstackio/json-to-graphql,= 1.0.3
@antstackio/shelbysam,= 1.1.7
@aryanhussain/my-angular-lib,= 0.0.23
@asyncapi/avro-schema-parser,= 3.0.25 || = 3.0.26
@asyncapi/bundler,= 0.6.5 || = 0.6.6
@asyncapi/cli,= 4.1.3 || = 4.1.2
@asyncapi/converter,= 1.6.3 || = 1.6.4
@asyncapi/diff,= 0.5.1 || = 0.5.2
@asyncapi/dotnet-rabbitmq-template,= 1.0.2 || = 1.0.1
@asyncapi/edavisualiser,= 1.2.2 || = 1.2.1
@asyncapi/generator,= 2.8.5 || = 2.8.6
@asyncapi/generator-components,= 0.3.2 || = 0.3.3
@asyncapi/generator-helpers,= 0.2.1 || = 0.2.2
@asyncapi/generator-react-sdk,= 1.1.5 || = 1.1.4
@asyncapi/go-watermill-template,= 0.2.77 || = 0.2.76
@asyncapi/html-template,= 3.3.2 || = 3.3.3
@asyncapi/java-spring-cloud-stream-template,= 0.13.5 || = 0.13.6
@asyncapi/java-spring-template,= 1.6.2 || = 1.6.1
@asyncapi/java-template,= 0.3.6 || = 0.3.5
@asyncapi/keeper,= 0.0.2 || = 0.0.3
@asyncapi/markdown-template,= 1.6.8 || = 1.6.9
@asyncapi/modelina,= 5.10.3 || = 5.10.2
@asyncapi/modelina-cli,= 5.10.3 || = 5.10.2
@asyncapi/multi-parser,= 2.2.1 || = 2.2.2
@asyncapi/nodejs-template,= 3.0.6 || = 3.0.5
@asyncapi/nodejs-ws-template,= 0.10.1 || = 0.10.2
@asyncapi/nunjucks-filters,= 2.1.1 || = 2.1.2
@asyncapi/openapi-schema-parser,= 3.0.25 || = 3.0.26
@asyncapi/optimizer,= 1.0.6 || = 1.0.5
@asyncapi/parser,= 3.4.1 || = 3.4.2
@asyncapi/php-template,= 0.1.1 || = 0.1.2
@asyncapi/problem,= 1.0.2 || = 1.0.1
@asyncapi/protobuf-schema-parser,= 3.5.2 || = 3.6.1 || = 3.5.3
@asyncapi/python-paho-template,= 0.2.15 || = 0.2.14
@asyncapi/react-component,= 2.6.7 || = 2.6.6
@asyncapi/server-api,= 0.16.24 || = 0.16.25
@asyncapi/specs,= 6.9.1 || = 6.10.1 || = 6.8.3 || = 6.8.2
@asyncapi/studio,= 1.0.3 || = 1.0.2
@asyncapi/web-component,= 2.6.7 || = 2.6.6
@bdkinc/knex-ibmi,= 0.5.7
@browserbasehq/bb9,= 1.2.21
@browserbasehq/director-ai,= 1.0.3
@browserbasehq/mcp,= 2.1.1
@browserbasehq/mcp-server-browserbase,= 2.4.2
@browserbasehq/sdk-functions,= 0.0.4
@browserbasehq/stagehand,= 3.0.4
@browserbasehq/stagehand-docs,= 1.0.1
@caretive/caret-cli,= 0.0.2
@chtijs/eslint-config,= 1.0.1
@clausehq/flows-step-httprequest,= 0.1.14
@clausehq/flows-step-jsontoxml,= 0.1.14
@clausehq/flows-step-mqtt,= 0.1.14
@clausehq/flows-step-sendgridemail,= 0.1.14
@clausehq/flows-step-taskscreateurl,= 0.1.14
@cllbk/ghl,= 1.3.1
@commute/bloom,= 1.0.3
@commute/market-data,= 1.0.2
@commute/market-data-chartjs,= 2.3.1
@dev-blinq/ai-qa-logic,= 1.0.19
@dev-blinq/blinqioclient,= 1.0.21
@dev-blinq/cucumber-js,= 1.0.131
@dev-blinq/cucumber_client,= 1.0.738
@dev-blinq/ui-systems,= 1.0.93
@ensdomains/address-encoder,= 1.1.5
@ensdomains/blacklist,= 1.0.1
@ensdomains/buffer,= 0.1.2
@ensdomains/ccip-read-cf-worker,= 0.0.4
@ensdomains/ccip-read-dns-gateway,= 0.1.1
@ensdomains/ccip-read-router,= 0.0.7
@ensdomains/ccip-read-worker-viem,= 0.0.4
@ensdomains/content-hash,= 3.0.1
@ensdomains/curvearithmetics,= 1.0.1
@ensdomains/cypress-metamask,= 1.2.1
@ensdomains/dnsprovejs,= 0.5.3
@ensdomains/dnssec-oracle-anchors,= 0.0.2
@ensdomains/dnssecoraclejs,= 0.2.9
@ensdomains/durin,= 0.1.2
@ensdomains/durin-middleware,= 0.0.2
@ensdomains/ens-archived-contracts,= 0.0.3
@ensdomains/ens-avatar,= 1.0.4
@ensdomains/ens-contracts,= 1.6.1
@ensdomains/ens-test-env,= 1.0.2
@ensdomains/ens-validation,= 0.1.1
@ensdomains/ensjs,= 4.0.3
@ensdomains/ensjs-react,= 0.0.5
@ensdomains/eth-ens-namehash,= 2.0.16
@ensdomains/hackathon-registrar,= 1.0.5
@ensdomains/hardhat-chai-matchers-viem,= 0.1.15
@ensdomains/hardhat-toolbox-viem-extended,= 0.0.6
@ensdomains/mock,= 2.1.52
@ensdomains/name-wrapper,= 1.0.1
@ensdomains/offchain-resolver-contracts,= 0.2.2
@ensdomains/op-resolver-contracts,= 0.0.2
@ensdomains/react-ens-address,= 0.0.32
@ensdomains/renewal,= 0.0.13
@ensdomains/renewal-widget,= 0.1.10
@ensdomains/reverse-records,= 1.0.1
@ensdomains/server-analytics,= 0.0.2
@ensdomains/solsha1,= 0.0.4
@ensdomains/subdomain-registrar,= 0.2.4
@ensdomains/test-utils,= 1.3.1
@ensdomains/thorin,= 0.6.51
@ensdomains/ui,= 3.4.6
@ensdomains/unicode-confusables,= 0.1.1
@ensdomains/unruggable-gateways,= 0.0.3
@ensdomains/vite-plugin-i18next-loader,= 4.0.4
@ensdomains/web3modal,= 1.10.2
@everreal/react-charts,= 2.0.2 || = 2.0.1
@everreal/validate-esmoduleinterop-imports,= 1.4.5 || = 1.4.4
@everreal/web-analytics,= 0.0.1 || = 0.0.2
@faq-component/core,= 0.0.4
@faq-component/react,= 1.0.1
@fishingbooker/browser-sync-plugin,= 1.0.5
@fishingbooker/react-loader,= 1.0.7
@fishingbooker/react-pagination,= 2.0.6
@fishingbooker/react-raty,= 2.0.1
@fishingbooker/react-swiper,= 0.1.5
@hapheus/n8n-nodes-pgp,= 1.5.1
@hover-design/core,= 0.0.1
@hover-design/react,= 0.2.1
@huntersofbook/auth-vue,= 0.4.2
@huntersofbook/core,= 0.5.1
@huntersofbook/core-nuxt,= 0.4.2
@huntersofbook/form-naiveui,= 0.5.1
@huntersofbook/i18n,= 0.8.2
@huntersofbook/ui,= 0.5.1
@hyperlook/telemetry-sdk,= 1.0.19
@ifelsedeveloper/protocol-contracts-svm-idl,= 0.1.2 || = 0.1.3
@ifings/design-system,= 4.9.2
@ifings/metatron3,= 0.1.5
@jayeshsadhwani/telemetry-sdk,= 1.0.14
@kvytech/cli,= 0.0.7
@kvytech/components,= 0.0.2
@kvytech/habbit-e2e-test,= 0.0.2
@kvytech/medusa-plugin-announcement,= 0.0.8
@kvytech/medusa-plugin-management,= 0.0.5
@kvytech/medusa-plugin-newsletter,= 0.0.5
@kvytech/medusa-plugin-product-reviews,= 0.0.9
@kvytech/medusa-plugin-promotion,= 0.0.2
@kvytech/web,= 0.0.2
@lessondesk/api-client,= 9.12.2 || = 9.12.3
@lessondesk/babel-preset,= 1.0.1
@lessondesk/electron-group-api-client,= 1.0.3
@lessondesk/eslint-config,= 1.4.2
@lessondesk/material-icons,= 1.0.3
@lessondesk/react-table-context,= 2.0.4
@lessondesk/schoolbus,= 5.2.2 || = 5.2.3
@livecms/live-edit,= 0.0.32
@livecms/nuxt-live-edit,= 1.9.2
@lokeswari-satyanarayanan/rn-zustand-expo-template,= 1.0.9
@louisle2/core,= 1.0.1
@louisle2/cortex-js,= 0.1.6
@lpdjs/firestore-repo-service,= 1.0.1
@lui-ui/lui-nuxt,= 0.1.1
@lui-ui/lui-tailwindcss,= 0.1.2
@lui-ui/lui-vue,= 1.0.13
@markvivanco/app-version-checker,= 1.0.2 || = 1.0.1
@mcp-use/cli,= 2.2.7 || = 2.2.6
@mcp-use/inspector,= 0.6.3 || = 0.6.2
@mcp-use/mcp-use,= 1.0.2 || = 1.0.1
@micado-digital/stadtmarketing-kufstein-external,= 1.9.1
@mizzle-dev/orm,= 0.0.2
@mparpaillon/connector-parse,= 1.0.1
@mparpaillon/imagesloaded,= 4.1.2
@mparpaillon/page,= 1.0.1
@ntnx/passport-wso2,= 0.0.3
@ntnx/t,= 0.0.101
@oku-ui/accordion,= 0.6.2
@oku-ui/alert-dialog,= 0.6.2
@oku-ui/arrow,= 0.6.2
@oku-ui/aspect-ratio,= 0.6.2
@oku-ui/avatar,= 0.6.2
@oku-ui/checkbox,= 0.6.3
@oku-ui/collapsible,= 0.6.2
@oku-ui/collection,= 0.6.2
@oku-ui/dialog,= 0.6.2
@oku-ui/direction,= 0.6.2
@oku-ui/dismissable-layer,= 0.6.2
@oku-ui/focus-guards,= 0.6.2
@oku-ui/focus-scope,= 0.6.2
@oku-ui/hover-card,= 0.6.2
@oku-ui/label,= 0.6.2
@oku-ui/menu,= 0.6.2
@oku-ui/motion,= 0.4.4
@oku-ui/motion-nuxt,= 0.2.2
@oku-ui/popover,= 0.6.2
@oku-ui/popper,= 0.6.2
@oku-ui/portal,= 0.6.2
@oku-ui/presence,= 0.6.2
@oku-ui/primitive,= 0.6.2
@oku-ui/primitives,= 0.7.9
@oku-ui/primitives-nuxt,= 0.3.1
@oku-ui/progress,= 0.6.2
@oku-ui/provide,= 0.6.2
@oku-ui/radio-group,= 0.6.2
@oku-ui/roving-focus,= 0.6.2
@oku-ui/scroll-area,= 0.6.2
@oku-ui/separator,= 0.6.2
@oku-ui/slider,= 0.6.2
@oku-ui/slot,= 0.6.2
@oku-ui/switch,= 0.6.2
@oku-ui/tabs,= 0.6.2
@oku-ui/toast,= 0.6.2
@oku-ui/toggle,= 0.6.2
@oku-ui/toggle-group,= 0.6.2
@oku-ui/toolbar,= 0.6.2
@oku-ui/tooltip,= 0.6.2
@oku-ui/use-composable,= 0.6.2
@oku-ui/utils,= 0.6.2
@oku-ui/visually-hidden,= 0.6.2
@orbitgtbelgium/mapbox-gl-draw-cut-polygon-mode,= 2.0.5
@orbitgtbelgium/mapbox-gl-draw-scale-rotate-mode,= 1.1.1
@orbitgtbelgium/orbit-components,= 1.2.9
@orbitgtbelgium/time-slider,= 1.0.187
@osmanekrem/bmad,= 1.0.6
@osmanekrem/error-handler,= 1.2.2
@pergel/cli,= 0.11.1
@pergel/module-box,= 0.6.1
@pergel/module-graphql,= 0.6.1
@pergel/module-ui,= 0.0.9
@pergel/nuxt,= 0.25.5
@posthog/agent,= 1.24.1
@posthog/ai,= 7.1.2
@posthog/automatic-cohorts-plugin,= 0.0.8
@posthog/bitbucket-release-tracker,= 0.0.8
@posthog/cli,= 0.5.15
@posthog/clickhouse,= 1.7.1
@posthog/core,= 1.5.6
@posthog/currency-normalization-plugin,= 0.0.8
@posthog/customerio-plugin,= 0.0.8
@posthog/databricks-plugin,= 0.0.8
@posthog/drop-events-on-property-plugin,= 0.0.8
@posthog/event-sequence-timer-plugin,= 0.0.8
@posthog/filter-out-plugin,= 0.0.8
@posthog/first-time-event-tracker,= 0.0.8
@posthog/geoip-plugin,= 0.0.8
@posthog/github-release-tracking-plugin,= 0.0.8
@posthog/gitub-star-sync-plugin,= 0.0.8
@posthog/heartbeat-plugin,= 0.0.8
@posthog/hedgehog-mode,= 0.0.42
@posthog/icons,= 0.36.1
@posthog/ingestion-alert-plugin,= 0.0.8
@posthog/intercom-plugin,= 0.0.8
@posthog/kinesis-plugin,= 0.0.8
@posthog/laudspeaker-plugin,= 0.0.8
@posthog/lemon-ui,= 0.0.1
@posthog/maxmind-plugin,= 0.1.6
@posthog/migrator3000-plugin,= 0.0.8
@posthog/netdata-event-processing,= 0.0.8
@posthog/nextjs,= 0.0.3
@posthog/nextjs-config,= 1.5.1
@posthog/nuxt,= 1.2.9
@posthog/pagerduty-plugin,= 0.0.8
@posthog/piscina,= 3.2.1
@posthog/plugin-contrib,= 0.0.6
@posthog/plugin-server,= 1.10.8
@posthog/plugin-unduplicates,= 0.0.8
@posthog/postgres-plugin,= 0.0.8
@posthog/react-rrweb-player,= 1.1.4
@posthog/rrdom,= 0.0.31
@posthog/rrweb,= 0.0.31
@posthog/rrweb-player,= 0.0.31
@posthog/rrweb-record,= 0.0.31
@posthog/rrweb-replay,= 0.0.19
@posthog/rrweb-snapshot,= 0.0.31
@posthog/rrweb-utils,= 0.0.31
@posthog/sendgrid-plugin,= 0.0.8
@posthog/siphash,= 1.1.2
@posthog/snowflake-export-plugin,= 0.0.8
@posthog/taxonomy-plugin,= 0.0.8
@posthog/twilio-plugin,= 0.0.8
@posthog/twitter-followers-plugin,= 0.0.8
@posthog/url-normalizer-plugin,= 0.0.8
@posthog/variance-plugin,= 0.0.8
@posthog/web-dev-server,= 1.0.5
@posthog/wizard,= 1.18.1
@posthog/zendesk-plugin,= 0.0.8
@postman/aether-icons,= 2.23.2 || = 2.23.3 || = 2.23.4
@postman/csv-parse,= 4.0.3 || = 4.0.5 || = 4.0.4
@postman/final-node-keytar,= 7.9.3 || = 7.9.1 || = 7.9.2
@postman/mcp-ui-client,= 5.5.2 || = 5.5.3 || = 5.5.1
@postman/node-keytar,= 7.9.4 || = 7.9.5 || = 7.9.6
@postman/pm-bin-linux-x64,= 1.24.3 || = 1.24.5 || = 1.24.4
@postman/pm-bin-macos-arm64,= 1.24.3 || = 1.24.5 || = 1.24.4
@postman/pm-bin-macos-x64,= 1.24.3 || = 1.24.5 || = 1.24.4
@postman/pm-bin-windows-x64,= 1.24.3 || = 1.24.5 || = 1.24.4
@postman/postman-collection-fork,= 4.3.3 || = 4.3.5 || = 4.3.4
@postman/postman-mcp-cli,= 1.0.4 || = 1.0.5 || = 1.0.3
@postman/postman-mcp-server,= 2.4.12 || = 2.4.10 || = 2.4.11
@postman/pretty-ms,= 6.1.2 || = 6.1.3 || = 6.1.1
@postman/secret-scanner-wasm,= 2.1.4 || = 2.1.3 || = 2.1.2
@postman/tunnel-agent,= 0.6.5 || = 0.6.7 || = 0.6.6
@postman/wdio-allure-reporter,= 0.0.7 || = 0.0.8 || = 0.0.9
@postman/wdio-junit-reporter,= 0.0.4 || = 0.0.5 || = 0.0.6
@pradhumngautam/common-app,= 1.0.2
@productdevbook/animejs-vue,= 0.2.1
@productdevbook/auth,= 0.2.2
@productdevbook/chatwoot,= 2.0.1
@productdevbook/motion,= 1.0.4
@productdevbook/ts-i18n,= 1.4.2
@pruthvi21/use-debounce,= 1.0.3
@quick-start-soft/quick-document-translator,= 1.4.2511142126
@quick-start-soft/quick-git-clean-markdown,= 1.4.2511142126
@quick-start-soft/quick-markdown,= 1.4.2511142126
@quick-start-soft/quick-markdown-compose,= 1.4.2506300029
@quick-start-soft/quick-markdown-image,= 1.4.2511142126
@quick-start-soft/quick-markdown-print,= 1.4.2511142126
@quick-start-soft/quick-markdown-translator,= 1.4.2509202331
@quick-start-soft/quick-remove-image-background,= 1.4.2511142126
@quick-start-soft/quick-task-refine,= 1.4.2511142126
@relyt/claude-context-core,= 0.1.1
@relyt/claude-context-mcp,= 0.1.1
@relyt/mcp-server-relytone,= 0.0.3
@sameepsi/sor,= 1.0.3
@sameepsi/sor2,= 2.0.2
@seezo/sdr-mcp-server,= 0.0.5
@seung-ju/next,= 0.0.2
@seung-ju/openapi-generator,= 0.0.4
@seung-ju/react-hooks,= 0.0.2
@seung-ju/react-native-action-sheet,= 0.2.1
@silgi/better-auth,= 0.8.1
@silgi/drizzle,= 0.8.4
@silgi/ecosystem,= 0.7.6
@silgi/graphql,= 0.7.15
@silgi/module-builder,= 0.8.8
@silgi/openapi,= 0.7.4
@silgi/permission,= 0.6.8
@silgi/ratelimit,= 0.2.1
@silgi/scalar,= 0.6.2
@silgi/yoga,= 0.7.1
@sme-ui/aoma-vevasound-metadata-lib,= 0.1.3
@strapbuild/react-native-date-time-picker,= 2.0.4
@strapbuild/react-native-perspective-image-cropper,= 0.4.15
@strapbuild/react-native-perspective-image-cropper-2,= 0.4.7
@strapbuild/react-native-perspective-image-cropper-poojan31,= 0.4.6
@suraj_h/medium-common,= 1.0.5
@thedelta/eslint-config,= 1.0.2
@tiaanduplessis/json,= 2.0.2 || = 2.0.3
@tiaanduplessis/react-progressbar,= 1.0.2 || = 1.0.1
@trackstar/angular-trackstar-link,= 1.0.2
@trackstar/react-trackstar-link,= 2.0.21
@trackstar/react-trackstar-link-upgrade,= 1.1.10
@trackstar/test-angular-package,= 0.0.9
@trackstar/test-package,= 1.1.5
@trefox/sleekshop-js,= 0.1.6
@trigo/atrix,= 7.0.1
@trigo/atrix-acl,= 4.0.2
@trigo/atrix-elasticsearch,= 2.0.1
@trigo/atrix-mongoose,= 1.0.2
@trigo/atrix-orientdb,= 1.0.2
@trigo/atrix-postgres,= 1.0.3
@trigo/atrix-pubsub,= 4.0.3
@trigo/atrix-redis,= 1.0.2
@trigo/atrix-soap,= 1.0.2
@trigo/atrix-swagger,= 3.0.1
@trigo/bool-expressions,= 4.1.3
@trigo/eslint-config-trigo,= 3.3.1
@trigo/fsm,= 3.4.2
@trigo/hapi-auth-signedlink,= 1.3.1
@trigo/jsdt,= 0.2.1
@trigo/keycloak-api,= 1.3.1
@trigo/node-soap,= 0.5.4
@trigo/pathfinder-ui-css,= 0.1.1
@trigo/trigo-hapijs,= 5.0.1
@trpc-rate-limiter/cloudflare,= 0.1.4
@trpc-rate-limiter/hono,= 0.1.4
@varsityvibe/api-client,= 1.3.36 || = 1.3.37
@varsityvibe/utils,= 5.0.6
@varsityvibe/validation-schemas,= 0.6.7 || = 0.6.8
@viapip/eslint-config,= 0.2.4
@vishadtyagi/full-year-calendar,= 0.1.11
@voiceflow/alexa-types,= 2.15.60 || = 2.15.61
@voiceflow/anthropic,= 0.4.4 || = 0.4.5
@voiceflow/api-sdk,= 3.28.59 || = 3.28.58
@voiceflow/backend-utils,= 5.0.1 || = 5.0.2
@voiceflow/base-types,= 2.136.3 || = 2.136.2
@voiceflow/body-parser,= 1.21.3 || = 1.21.2
@voiceflow/chat-types,= 2.14.59 || = 2.14.58
@voiceflow/circleci-config-sdk-orb-import,= 0.2.1 || = 0.2.2
@voiceflow/commitlint-config,= 2.6.2 || = 2.6.1
@voiceflow/common,= 8.9.1 || = 8.9.2
@voiceflow/default-prompt-wrappers,= 1.7.4 || = 1.7.3
@voiceflow/dependency-cruiser-config,= 1.8.11 || = 1.8.12
@voiceflow/dtos-interact,= 1.40.2 || = 1.40.1
@voiceflow/encryption,= 0.3.2 || = 0.3.3
@voiceflow/eslint-config,= 7.16.4 || = 7.16.5
@voiceflow/eslint-plugin,= 1.6.2 || = 1.6.1
@voiceflow/exception,= 1.10.1 || = 1.10.2
@voiceflow/fetch,= 1.11.1 || = 1.11.2
@voiceflow/general-types,= 3.2.22 || = 3.2.23
@voiceflow/git-branch-check,= 1.4.3 || = 1.4.4
@voiceflow/google-dfes-types,= 2.17.12 || = 2.17.13
@voiceflow/google-types,= 2.21.12 || = 2.21.13
@voiceflow/husky-config,= 1.3.2 || = 1.3.1
@voiceflow/logger,= 2.4.3 || = 2.4.2
@voiceflow/metrics,= 1.5.2 || = 1.5.1
@voiceflow/natural-language-commander,= 0.5.2 || = 0.5.3
@voiceflow/nestjs-common,= 2.75.3 || = 2.75.2
@voiceflow/nestjs-mongodb,= 1.3.2 || = 1.3.1
@voiceflow/nestjs-rate-limit,= 1.3.2 || = 1.3.3
@voiceflow/nestjs-redis,= 1.3.2 || = 1.3.1
@voiceflow/nestjs-timeout,= 1.3.2 || = 1.3.1
@voiceflow/npm-package-json-lint-config,= 1.1.2 || = 1.1.1
@voiceflow/openai,= 3.2.3 || = 3.2.2
@voiceflow/pino,= 6.11.4 || = 6.11.3
@voiceflow/pino-pretty,= 4.4.1 || = 4.4.2
@voiceflow/prettier-config,= 1.10.1 || = 1.10.2
@voiceflow/react-chat,= 1.65.3 || = 1.65.4
@voiceflow/runtime,= 1.29.2 || = 1.29.1
@voiceflow/runtime-client-js,= 1.17.2 || = 1.17.3
@voiceflow/sdk-runtime,= 1.43.2 || = 1.43.1
@voiceflow/secrets-provider,= 1.9.2 || = 1.9.3
@voiceflow/semantic-release-config,= 1.4.2 || = 1.4.1
@voiceflow/serverless-plugin-typescript,= 2.1.8 || = 2.1.7
@voiceflow/slate-serializer,= 1.7.4 || = 1.7.3
@voiceflow/stitches-react,= 2.3.3 || = 2.3.2
@voiceflow/storybook-config,= 1.2.3 || = 1.2.2
@voiceflow/stylelint-config,= 1.1.2 || = 1.1.1
@voiceflow/test-common,= 2.1.1 || = 2.1.2
@voiceflow/tsconfig,= 1.12.1 || = 1.12.2
@voiceflow/tsconfig-paths,= 1.1.5 || = 1.1.4
@voiceflow/utils-designer,= 1.74.20 || = 1.74.19
@voiceflow/verror,= 1.1.5 || = 1.1.4
@voiceflow/vite-config,= 2.6.2 || = 2.6.3
@voiceflow/vitest-config,= 1.10.3 || = 1.10.2
@voiceflow/voice-types,= 2.10.58 || = 2.10.59
@voiceflow/voiceflow-types,= 3.32.45 || = 3.32.46
@voiceflow/widget,= 1.7.18 || = 1.7.19
@vucod/email,= 0.0.3
@zapier/ai-actions,= 0.1.18 || = 0.1.19 || = 0.1.20
@zapier/ai-actions-react,= 0.1.13 || = 0.1.12 || = 0.1.14
@zapier/babel-preset-zapier,= 6.4.2 || = 6.4.1 || = 6.4.3
@zapier/browserslist-config-zapier,= 1.0.4 || = 1.0.5 || = 1.0.3
@zapier/eslint-plugin-zapier,= 11.0.5 || = 11.0.3 || = 11.0.4
@zapier/mcp-integration,= 3.0.3 || = 3.0.1 || = 3.0.2
@zapier/secret-scrubber,= 1.1.5 || = 1.1.3 || = 1.1.4
@zapier/spectral-api-ruleset,= 1.9.3 || = 1.9.2 || = 1.9.1
@zapier/stubtree,= 0.1.4 || = 0.1.3 || = 0.1.2
@zapier/zapier-sdk,= 0.15.7 || = 0.15.6 || = 0.15.5
ai-crowl-shield,= 1.0.7
arc-cli-fc,= 1.0.1
asciitranslator,= 1.0.3
asyncapi-preview,= 1.0.2 || = 1.0.1
atrix,= 1.0.1
atrix-mongoose,= 1.0.1
automation_model,= 1.0.491
avvvatars-vue,= 1.1.2
axios-builder,= 1.2.1
axios-cancelable,= 1.0.2 || = 1.0.1
axios-timed,= 1.0.2 || = 1.0.1
babel-preset-kinvey-flex-service,= 0.1.1
barebones-css,= 1.1.3 || = 1.1.4
benmostyn-frame-print,= 1.0.1
best_gpio_controller,= 1.0.10
better-auth-nuxt,= 0.0.10
better-queue-nedb,= 0.1.5
bidirectional-adapter,= 1.2.3 || = 1.2.2 || = 1.2.5 || = 1.2.4
blinqio-executions-cli,= 1.0.41
blob-to-base64,= 1.0.3
bool-expressions,= 0.1.2
buffered-interpolation-babylon6,= 0.2.8
bun-plugin-httpfile,= 0.1.1
bytecode-checker-cli,= 1.0.10 || = 1.0.9 || = 1.0.8 || = 1.0.11
bytes-to-x,= 1.0.1
calc-loan-interest,= 1.0.4
capacitor-plugin-apptrackingios,= 0.0.21
capacitor-plugin-purchase,= 0.1.1
capacitor-plugin-scgssigninwithgoogle,= 0.0.5
capacitor-purchase-history,= 0.0.10
capacitor-voice-recorder-wav,= 6.0.3
ceviz,= 0.0.5
chrome-extension-downloads,= 0.0.3 || = 0.0.4
claude-token-updater,= 1.0.3
coinmarketcap-api,= 3.1.3 || = 3.1.2
colors-regex,= 2.0.1
command-irail,= 0.5.4
compare-obj,= 1.1.2 || = 1.1.1
composite-reducer,= 1.0.4 || = 1.0.5 || = 1.0.2 || = 1.0.3
count-it-down,= 1.0.2 || = 1.0.1
cpu-instructions,= 0.0.14
create-director-app,= 0.1.1
create-glee-app,= 0.2.3 || = 0.2.2
create-hardhat3-app,= 1.1.2 || = 1.1.3 || = 1.1.1 || = 1.1.4
create-kinvey-flex-service,= 0.2.1
create-mcp-use-app,= 0.5.4 || = 0.5.3
create-silgi,= 0.3.1
crypto-addr-codec,= 0.1.9
css-dedoupe,= 0.1.2
csv-tool-cli,= 1.2.1
dashboard-empty-state,= 1.0.3
designstudiouiux,= 1.0.1
devstart-cli,= 1.0.6
dialogflow-es,= 1.1.2 || = 1.1.3 || = 1.1.1 || = 1.1.4
discord-bot-server,= 0.1.2
docusaurus-plugin-vanilla-extract,= 1.0.3
dont-go,= 1.1.2
dotnet-template,= 0.0.3 || = 0.0.4
drop-events-on-property-plugin,= 0.0.2
easypanel-sdk,= 0.3.2
electron-volt,= 0.0.2
email-deliverability-tester,= 1.1.1
enforce-branch-name,= 1.1.3
esbuild-plugin-brotli,= 0.2.1
esbuild-plugin-eta,= 0.1.1
esbuild-plugin-httpfile,= 0.4.1
eslint-config-kinvey-flex-service,= 0.1.1
eslint-config-nitpicky,= 4.0.1
eslint-config-trigo,= 22.0.2
eslint-config-zeallat-base,= 1.0.4
ethereum-ens,= 0.8.1
evm-checkcode-cli,= 1.0.14 || = 1.0.12 || = 1.0.15 || = 1.0.13
exact-ticker,= 0.3.5
expo-audio-session,= 0.2.1
expo-router-on-rails,= 0.0.4
express-starter-template,= 1.0.10
expressos,= 1.1.3
fat-fingered,= 1.0.2 || = 1.0.1
feature-flip,= 1.0.2 || = 1.0.1
firestore-search-engine,= 1.2.3
fittxt,= 1.0.3 || = 1.0.2
flapstacks,= 1.0.2 || = 1.0.1
flatten-unflatten,= 1.0.2 || = 1.0.1
formik-error-focus,= 2.0.1
formik-store,= 1.0.1
frontity-starter-theme,= 1.0.1
fuzzy-finder,= 1.0.6 || = 1.0.5
gate-evm-check-code2,= 2.0.6 || = 2.0.5 || = 2.0.4 || = 2.0.3
gate-evm-tools-test,= 1.0.6 || = 1.0.5 || = 1.0.8 || = 1.0.7
gatsby-plugin-antd,= 2.2.1
gatsby-plugin-cname,= 1.0.2 || = 1.0.1
generator-meteor-stock,= 0.1.6
generator-ng-itobuz,= 0.0.15
get-them-args,= 1.3.3
github-action-for-generator,= 2.1.27 || = 2.1.28
gitsafe,= 1.0.5
go-template,= 0.1.9 || = 0.1.8
gulp-inject-envs,= 1.2.2 || = 1.2.1
haufe-axera-api-client,= 0.0.1 || = 0.0.2
hope-mapboxdraw,= 0.1.1
hopedraw,= 1.0.3
hover-design-prototype,= 0.0.5
httpness,= 1.0.3 || = 1.0.2
hyper-fullfacing,= 1.0.3
hyperterm-hipster,= 1.0.7
ids-css,= 1.5.1
ids-enterprise-mcp-server,= 0.0.2
ids-enterprise-ng,= 20.1.6
ids-enterprise-typings,= 20.1.6
image-to-uri,= 1.0.2 || = 1.0.1
insomnia-plugin-random-pick,= 1.0.4
invo,= 0.2.2
iron-shield-miniapp,= 0.0.2
ito-button,= 8.0.3
itobuz-angular,= 0.0.1
itobuz-angular-auth,= 8.0.11
itobuz-angular-button,= 8.0.11
jacob-zuma,= 1.0.2 || = 1.0.1
jaetut-varit-test,= 1.0.2
jan-browser,= 0.13.1
jquery-bindings,= 1.1.2 || = 1.1.3
jsonsurge,= 1.0.7
just-toasty,= 1.7.1
kill-port,= 2.0.2 || = 2.0.3
kinetix-default-token-list,= 1.0.5
kinvey-cli-wrapper,= 0.3.1
kinvey-flex-scripts,= 0.5.1
kns-error-code,= 1.0.8
korea-administrative-area-geo-json-util,= 1.0.7
kwami,= 1.5.9 || = 1.5.10
lang-codes,= 1.0.2 || = 1.0.1
license-o-matic,= 1.2.2 || = 1.2.1
lint-staged-imagemin,= 1.3.2 || = 1.3.1
lite-serper-mcp-server,= 0.2.2
lui-vue-test,= 0.70.9
luno-api,= 1.2.3
m25-transaction-utils,= 1.1.16
manual-billing-system-miniapp-api,= 1.3.1
mcp-use,= 1.4.2 || = 1.4.3
medusa-plugin-announcement,= 0.0.3
medusa-plugin-logs,= 0.0.17
medusa-plugin-momo,= 0.0.68
medusa-plugin-product-reviews-kvy,= 0.0.4
medusa-plugin-zalopay,= 0.0.40
mod10-check-digit,= 1.0.1
mon-package-react-typescript,= 1.0.1
my-saeed-lib,= 0.1.1
n8n-nodes-tmdb,= 0.5.1
n8n-nodes-vercel-ai-sdk,= 0.1.7
n8n-nodes-viral-app,= 0.2.5
nanoreset,= 7.0.2 || = 7.0.1
next-circular-dependency,= 1.0.3 || = 1.0.2
next-simple-google-analytics,= 1.1.2 || = 1.1.1
next-styled-nprogress,= 1.0.4 || = 1.0.5
ngx-useful-swiper-prosenjit,= 9.0.2
ngx-wooapi,= 12.0.1
nitro-graphql,= 1.5.12
nitro-kutu,= 0.1.1
nitrodeploy,= 1.0.8
nitroping,= 0.1.1
normal-store,= 1.3.2 || = 1.3.4 || = 1.3.1 || = 1.3.3
nuxt-keycloak,= 0.2.2
obj-to-css,= 1.0.3 || = 1.0.2
okta-react-router-6,= 5.0.1
open2internet,= 0.1.1
orbit-boxicons,= 2.1.3
orbit-nebula-draw-tools,= 1.0.10
orbit-nebula-editor,= 1.0.2
orbit-soap,= 0.43.13
orchestrix,= 12.1.2
package-tester,= 1.0.1
parcel-plugin-asset-copier,= 1.1.2 || = 1.1.3
pdf-annotation,= 0.0.2
pergel,= 0.13.2
pergeltest,= 0.0.25
piclite,= 1.0.1
pico-uid,= 1.0.4 || = 1.0.3
pkg-readme,= 1.1.1
poper-react-sdk,= 0.1.2
posthog-docusaurus,= 2.0.6
posthog-js,= 1.297.3
posthog-node,= 5.13.3 || = 5.11.3 || = 4.18.1
posthog-plugin-hello-world,= 1.0.1
posthog-react-native,= 4.11.1 || = 4.12.5
posthog-react-native-session-replay,= 1.2.2
prime-one-table,= 0.0.19
prompt-eng,= 1.0.50
prompt-eng-server,= 1.0.18
puny-req,= 1.0.3
quickswap-ads-list,= 1.0.33
quickswap-default-staking-list,= 1.0.11
quickswap-default-staking-list-address,= 1.0.55
quickswap-default-token-list,= 1.5.16
quickswap-router-sdk,= 1.0.1
quickswap-sdk,= 3.0.44
quickswap-smart-order-router,= 1.0.1
quickswap-token-lists,= 1.0.3
quickswap-v2-sdk,= 2.0.1
ra-auth-firebase,= 1.0.3
ra-data-firebase,= 1.0.8 || = 1.0.7
react-component-taggers,= 0.1.9
react-data-to-export,= 1.0.1
react-element-prompt-inspector,= 0.1.18
react-favic,= 1.0.2
react-hook-form-persist,= 3.0.1 || = 3.0.2
react-jam-icons,= 1.0.2 || = 1.0.1
react-keycloak-context,= 1.0.9 || = 1.0.8
react-library-setup,= 0.0.6
react-linear-loader,= 1.0.2
react-micromodal.js,= 1.0.2 || = 1.0.1
react-native-datepicker-modal,= 1.3.2 || = 1.3.1
react-native-email,= 2.1.1 || = 2.1.2
react-native-fetch,= 2.0.2 || = 2.0.1
react-native-get-pixel-dimensions,= 1.0.2 || = 1.0.1
react-native-google-maps-directions,= 2.1.2
react-native-jam-icons,= 1.0.2 || = 1.0.1
react-native-log-level,= 1.2.2 || = 1.2.1
react-native-modest-checkbox,= 3.3.1
react-native-modest-storage,= 2.1.1
react-native-phone-call,= 1.2.2 || = 1.2.1
react-native-retriable-fetch,= 2.0.2 || = 2.0.1
react-native-use-modal,= 1.0.3
react-native-view-finder,= 1.2.2 || = 1.2.1
react-native-websocket,= 1.0.4 || = 1.0.3
react-native-worklet-functions,= 3.3.3
react-packery-component,= 1.0.3
react-qr-image,= 1.1.1
react-scrambled-text,= 1.0.4
rediff,= 1.0.5
rediff-viewer,= 0.0.7
redux-forge,= 2.5.3
redux-router-kit,= 1.2.3 || = 1.2.2 || = 1.2.4
revenuecat,= 1.0.1
rollup-plugin-httpfile,= 0.2.1
sa-company-registration-number-regex,= 1.0.2 || = 1.0.1
sa-id-gen,= 1.0.4 || = 1.0.5
samesame,= 1.0.3
scgs-capacitor-subscribe,= 1.0.11
scgsffcreator,= 1.0.5
schob,= 1.0.3
selenium-session,= 1.0.5
selenium-session-client,= 1.0.4
set-nested-prop,= 2.0.2 || = 2.0.1
shelf-jwt-sessions,= 0.1.2
shell-exec,= 1.1.3 || = 1.1.4
shinhan-limit-scrap,= 1.0.3
silgi,= 0.43.30
simplejsonform,= 1.0.1
skills-use,= 0.1.1 || = 0.1.2
solomon-api-stories,= 1.0.2
solomon-v3-stories,= 1.15.6
solomon-v3-ui-wrapper,= 1.6.1
soneium-acs,= 1.0.1
sort-by-distance,= 2.0.1
south-african-id-info,= 1.0.2
stat-fns,= 1.0.1
stoor,= 2.3.2
sufetch,= 0.4.1
super-commit,= 1.0.1
svelte-autocomplete-select,= 1.1.1
svelte-toasty,= 1.1.2 || = 1.1.3
tanstack-shadcn-table,= 1.1.5
tavily-module,= 1.0.1
tcsp,= 2.0.2
tcsp-draw-test,= 1.0.5
tcsp-test-vd,= 2.4.4
template-lib,= 1.1.3 || = 1.1.4
template-micro-service,= 1.0.3 || = 1.0.2
tenacious-fetch,= 2.3.3 || = 2.3.2
test-foundry-app,= 1.0.4 || = 1.0.3 || = 1.0.2 || = 1.0.1
test-hardhat-app,= 1.0.4 || = 1.0.3 || = 1.0.2 || = 1.0.1
test23112222-api,= 1.0.1
tiaan,= 1.0.2
tiptap-shadcn-vue,= 0.2.1
token.js-fork,= 0.7.32
toonfetch,= 0.3.2
trigo-react-app,= 4.1.2
ts-relay-cursor-paging,= 2.1.1
typeface-antonio-complete,= 1.0.5
typefence,= 1.2.3 || = 1.2.2
typeorm-orbit,= 0.2.27
unadapter,= 0.1.3
undefsafe-typed,= 1.0.4 || = 1.0.3
unemail,= 0.3.1
uniswap-router-sdk,= 1.6.2
uniswap-smart-order-router,= 3.16.26
uniswap-test-sdk-core,= 4.0.8
unsearch,= 0.0.3
uplandui,= 0.5.4
upload-to-play-store,= 1.0.2 || = 1.0.1
url-encode-decode,= 1.0.2 || = 1.0.1
use-unsaved-changes,= 1.0.9
v-plausible,= 1.2.1
valid-south-african-id,= 1.0.3
valuedex-sdk,= 3.0.5
vf-oss-template,= 1.0.4 || = 1.0.3 || = 1.0.2 || = 1.0.1
victoria-wallet-constants,= 0.1.1 || = 0.1.2
victoria-wallet-core,= 0.1.1 || = 0.1.2
victoria-wallet-type,= 0.1.1 || = 0.1.2
victoria-wallet-utils,= 0.1.1 || = 0.1.2
victoria-wallet-validator,= 0.1.1 || = 0.1.2
victoriaxoaquyet-wallet-core,= 0.2.1 || = 0.2.2
vite-plugin-httpfile,= 0.2.1
vue-browserupdate-nuxt,= 1.0.5
wallet-evm,= 0.3.2 || = 0.3.1
wallet-type,= 0.1.1 || = 0.1.2
web-scraper-mcp,= 1.1.4
web-types-htmx,= 0.1.1
web-types-lit,= 0.1.1
webpack-loader-httpfile,= 0.2.1
wellness-expert-ng-gallery,= 5.1.1
wenk,= 1.0.10 || = 1.0.9
zapier-async-storage,= 1.0.3 || = 1.0.2 || = 1.0.1
zapier-platform-cli,= 18.0.4 || = 18.0.3 || = 18.0.2
zapier-platform-core,= 18.0.4 || = 18.0.3 || = 18.0.2
zapier-platform-legacy-scripting-runner,= 4.0.3 || = 4.0.2 || = 4.0.4
zapier-platform-schema,= 18.0.4 || = 18.0.3 || = 18.0.2
zapier-scripts,= 7.8.4 || = 7.8.3
zuper-cli,= 1.0.1
zuper-sdk,= 1.0.57
zuper-stream,= 2.0.9
"""

        f = StringIO(SHAI_HULUD_CSV.strip())
        reader = csv.DictReader(f)

        for row in reader:
            pkg = (row.get("Package") or "").strip()
            version_expr_raw = (row.get("Version") or "").strip()
            if not pkg or not version_expr_raw:
                continue

            # Normalise version expression for NpmSpec:
            # remove spaces so "= 1.0.0 || = 1.0.1" → "=1.0.0||=1.0.1"
            version_expr = version_expr_raw.replace(" ", "")

            vuln_entry = {
                "range": version_expr,
                "severity": "HIGH",  # treat malicious packages as high severity
                "cve_id": "MALICIOUS-PACKAGE-SHAI-HULUD-2",
                "description": "Package reported as malicious in the shai-hulud-2 npm compromise list",
            }

            if pkg not in builtin_vulns:
                builtin_vulns[pkg] = []
            builtin_vulns[pkg].append(vuln_entry)

    def _load_builtin_vulnerabilities(self):
        """
        Load built-in CVE-based vulnerabilities + shai-hulud-2 malicious packages
        into the SQLite DB and the in-memory dict.
        """
        builtin_vulns: Dict[str, List[Dict]] = {
            # 2024/2021 high-profile CVEs (examples – extend as needed)
            "braces": [
                {
                    "range": "<3.0.3",
                    "severity": "HIGH",
                    "cve_id": "CVE-2024-4068",
                    "description": "ReDoS vulnerability in braces package",
                }
            ],
            "ws": [
                {
                    "range": ">=8.0.0 <8.17.1",
                    "severity": "HIGH",
                    "cve_id": "CVE-2024-37890",
                    "description": "Resource exhaustion / unhandled exception",
                },
                {
                    "range": ">=7.0.0 <7.4.6",
                    "severity": "HIGH",
                    "cve_id": "CVE-2021-32640",
                    "description": "ReDoS vulnerability in Sec-WebSocket-Protocol header parsing",
                },
                {
                    "range": ">=6.0.0 <6.2.2",
                    "severity": "HIGH",
                    "cve_id": "CVE-2021-32640",
                    "description": "ReDoS vulnerability in Sec-WebSocket-Protocol header parsing",
                },
            ],
            "lodash": [
                {
                    "range": "<4.17.21",
                    "severity": "HIGH",
                    "cve_id": "CVE-2021-23337",
                    "description": "Command injection via template function",
                }
            ],
            "minimist": [
                {
                    "range": "<1.2.6",
                    "severity": "HIGH",
                    "cve_id": "CVE-2020-7598",
                    "description": "Prototype pollution in minimist",
                }
            ],
            "tar": [
                {
                    "range": "<4.4.15 || >=5.0.0 <5.0.7 || >=6.0.0 <6.1.2",
                    "severity": "HIGH",
                    "cve_id": "CVE-2021-32804",
                    "description": "Path traversal in tar archive extraction",
                }
            ],
            "got": [
                {
                    "range": "<11.8.5",
                    "severity": "MEDIUM",
                    "cve_id": "CVE-2022-33987",
                    "description": "HTTP request smuggling in got",
                }
            ],
        }

        # Extend with the shai-hulud-2 malicious packages
        self._load_shai_hulud_malicious_packages(builtin_vulns)

        # Insert into SQLite DB
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        for package_name, vulns in builtin_vulns.items():
            for vuln in vulns:
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO vulnerabilities
                    (package_name, version_range, severity, cve_id, description, source)
                    VALUES (?, ?, ?, ?, ?, 'builtin')
                    """,
                    (
                        package_name,
                        vuln["range"],
                        vuln["severity"],
                        vuln.get("cve_id"),
                        vuln.get("description"),
                    ),
                )
        conn.commit()
        conn.close()

        self.vulnerabilities = builtin_vulns

    def is_vulnerable(self, package_name: str, version: str) -> List[Dict]:
        """Check if a package version is vulnerable"""
        vulnerabilities: List[Dict] = []

        if package_name in self.vulnerabilities:
            for vuln in self.vulnerabilities[package_name]:
                if self._is_version_in_range(version, vuln["range"]):
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _is_version_in_range(self, version: str, range_expr: str) -> bool:
        """Check if version falls within vulnerable range"""
        try:
            spec = NpmSpec(range_expr)
            normalized_version = version.lstrip("^~")
            return Version(normalized_version) in spec
        except Exception:
            return False

# ------------------ Enhanced Logging ------------------
def setup_logging(config: ScanConfig):
    """Setup enhanced logging with different levels"""
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    if config.enable_logging:
        logging.basicConfig(
            level=getattr(logging, config.log_level.upper()),
            format=log_format,
            handlers=[
                logging.FileHandler(f'npm3guard_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
                logging.StreamHandler()
            ]
        )
    else:
        logging.basicConfig(level=logging.CRITICAL)

# ------------------ Enhanced Notification System ------------------
class NotificationManager:
    """Enhanced notification system with detailed Slack reporting"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
    
    def send_detailed_scan_alert(self, scan_summary: Dict, vulnerabilities: List[Dict]):
        """Send detailed scan completion alert with vulnerability breakdown"""
        if not self.config.slack_webhook:
            return
            
        total_vulns = scan_summary.get('total_vulnerabilities', 0)
        if total_vulns == 0:
            return  # Don't send alerts for clean scans
            
        org_name = scan_summary.get('username', 'unknown')
        high_count = scan_summary.get('high_severity', 0)
        medium_count = scan_summary.get('medium_severity', 0)
        low_count = scan_summary.get('low_severity', 0)
        
        # Create detailed message
        alert_message = f"🚨 *NPM3Guard Security Alert*\n\n"
        alert_message += f"*Total {total_vulns} vulnerabilities found in `{org_name}`*\n\n"
        alert_message += f"📊 *Severity Breakdown:*\n"
        alert_message += f"• 🔴 High severity: {high_count}\n"
        alert_message += f"• 🟡 Medium severity: {medium_count}\n"
        alert_message += f"• 🟢 Low severity: {low_count}\n\n"
        
        # Group vulnerabilities by repository
        vulns_by_repo = {}
        for vuln in vulnerabilities:
            repo = vuln.get('repository', 'unknown')
            if repo not in vulns_by_repo:
                vulns_by_repo[repo] = []
            vulns_by_repo[repo].append(vuln)
        
        alert_message += f"📁 *Affected Repositories ({len(vulns_by_repo)}):*\n"
        
        for repo, repo_vulns in vulns_by_repo.items():
            repo_high = sum(1 for v in repo_vulns if v.get('severity') == 'HIGH')
            repo_medium = sum(1 for v in repo_vulns if v.get('severity') == 'MEDIUM')  
            repo_low = sum(1 for v in repo_vulns if v.get('severity') == 'LOW')
            
            alert_message += f"\n*{repo}* ({len(repo_vulns)} vulnerabilities)\n"
            if repo_high > 0:
                alert_message += f"  🔴 {repo_high} high"
            if repo_medium > 0:
                alert_message += f"  🟡 {repo_medium} medium"
            if repo_low > 0:
                alert_message += f"  🟢 {repo_low} low"
            alert_message += "\n"
            
            # List top vulnerabilities for this repo (limit to 5)
            for vuln in repo_vulns[:5]:
                severity_emoji = "🔴" if vuln.get('severity') == 'HIGH' else "🟡" if vuln.get('severity') == 'MEDIUM' else "🟢"
                alert_message += f"  {severity_emoji} `{vuln.get('package', 'unknown')}` v{vuln.get('clean_version', 'unknown')} - {vuln.get('cve_id', 'N/A')}\n"
                alert_message += f"     📍 {vuln.get('file', 'unknown')}\n"
                alert_message += f"     💡 {vuln.get('description', 'No description')}\n"
            
            if len(repo_vulns) > 5:
                alert_message += f"  ... and {len(repo_vulns) - 5} more\n"
        
        alert_message += f"\n⏰ *Scan completed:* {scan_summary.get('scan_time', 'unknown')}\n"
        alert_message += f"🔧 *Tool:* NPM3Guard v2.3 Enterprise\n"
        alert_message += f"🔍 *Platform:* {scan_summary.get('platform', 'GitHub')}\n"
        alert_message += f"♻️ *Recursive scan:* {'✅ Enabled' if scan_summary.get('recursive_scan', False) else '❌ Disabled'}\n"
        
        # Send to Slack
        self._send_slack_message(alert_message)
        
        if self.config.teams_webhook:
            self._send_teams_alert(f"Security Alert: {total_vulns} vulnerabilities found in {org_name}")
    
    def send_alert(self, message: str, severity: str = "INFO"):
        """Send simple alert to configured notification channels"""
        formatted_message = f"[{severity}] NPM3Guard Alert: {message}"
        
        if self.config.slack_webhook:
            self._send_slack_message(formatted_message)
        
        if self.config.teams_webhook:
            self._send_teams_alert(formatted_message)
    
    def _send_slack_message(self, message: str):
        """Send formatted message to Slack"""
        try:
            payload = {
                "text": message,
                "username": "NPM3Guard",
                "icon_emoji": ":warning:",
                "mrkdwn": True
            }
            response = requests.post(self.config.slack_webhook, json=payload, timeout=10)
            if response.status_code != 200:
                logging.error(f"Slack alert failed: {response.status_code} {response.text}")
            else:
                logging.info("Detailed Slack alert sent successfully")
        except Exception as e:
            logging.error(f"Slack alert error: {e}")
    
    def _send_teams_alert(self, message: str):
        """Send alert to Microsoft Teams"""
        try:
            payload = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": "0076D7",
                "summary": "NPM3Guard Security Alert",
                "sections": [{
                    "activityTitle": "NPM3Guard Security Scanner",
                    "activitySubtitle": "Vulnerability Detection Alert",
                    "text": message
                }]
            }
            response = requests.post(self.config.teams_webhook, json=payload, timeout=10)
            if response.status_code != 200:
                logging.error(f"Teams alert failed: {response.status_code} {response.text}")
        except Exception as e:
            logging.error(f"Teams alert error: {e}")

# ------------------ Enhanced Git Platform Handlers ------------------
class GitPlatformHandler:
    """Base class for Git platform handlers"""
    
    def __init__(self, config: ScanConfig, notification_manager: NotificationManager):
        self.config = config
        self.notification_manager = notification_manager
        self.session = requests.Session()
        self.session.timeout = config.timeout
        self.dependency_files = ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"]
    
    def _make_request_with_retry(self, url: str, headers: Dict = None, **kwargs) -> Optional[requests.Response]:
        """Make HTTP request with retry logic and rate limiting"""
        headers = headers or {}
        
        for attempt in range(self.config.retries):
            try:
                time.sleep(self.config.rate_limit_delay)
                response = self.session.get(url, headers=headers, **kwargs)
                
                if response.status_code == 200:
                    return response
                elif response.status_code == 403:
                    logging.warning(f"Rate limited. Waiting 60 seconds... (Attempt {attempt + 1})")
                    time.sleep(60)
                elif response.status_code == 401:
                    logging.error("Authentication failed. Check your token permissions.")
                    return None
                else:
                    logging.warning(f"HTTP {response.status_code} for {url}")
                    
            except requests.exceptions.RequestException as e:
                logging.error(f"Request failed (attempt {attempt + 1}): {e}")
                if attempt < self.config.retries - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff
        
        return None

class GitHubHandler(GitPlatformHandler):
    """Enhanced GitHub API handler with organization support and detailed alerts"""
    
    def __init__(self, token: str, config: ScanConfig, notification_manager: NotificationManager):
        super().__init__(config, notification_manager)
        self.token = token
        self.base_url = "https://api.github.com"
        self.headers = {
            "Authorization": f"Bearer {token}" if token else {},
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
    
    def get_account_type(self, username: str) -> Optional[str]:
        """Determine if username is a User or Organization"""
        url = f"{self.base_url}/users/{username}"
        response = self._make_request_with_retry(url, headers=self.headers)
        
        if response and response.status_code == 200:
            data = response.json()
            account_type = data.get('type', 'User')
            logging.info(f"Detected account type for '{username}': {account_type}")
            return account_type
        else:
            logging.warning(f"Could not determine account type for '{username}', defaulting to User")
            return "User"
    
    def fetch_repositories(self, username: str) -> List[Dict]:
        """Fetch all repositories for a user/organization with pagination and proper endpoint detection"""
        account_type = self.get_account_type(username)
        
        # Choose correct API endpoint based on account type
        if account_type == "Organization":
            base_endpoint = f"{self.base_url}/orgs/{username}/repos"
        else:
            base_endpoint = f"{self.base_url}/users/{username}/repos"
        
        repos = []
        page = 1
        per_page = 100
        
        while True:
            url = base_endpoint
            params = {
                "per_page": per_page, 
                "page": page, 
                "type": "all",  # Include all types: owner, member, etc.
                "sort": "updated",
                "direction": "desc"
            }
            
            response = self._make_request_with_retry(url, headers=self.headers, params=params)
            if not response:
                logging.error(f"Failed to fetch repositories from {url}")
                break
            
            data = response.json()
            if not data:
                break
            
            repos.extend(data)
            logging.info(f"Fetched {len(data)} repositories (page {page}) from {account_type}")
            
            # Check if we have more pages
            if len(data) < per_page:
                break
            page += 1
        
        logging.info(f"Total repositories found for '{username}' ({account_type}): {len(repos)}")
        return repos
    
    def fetch_repository_tree(self, repo_full_name: str, branch: str = "main") -> List[Dict]:
        """Fetch complete file tree of a repository recursively"""
        url = f"{self.base_url}/repos/{repo_full_name}/git/trees/{branch}"
        params = {"recursive": "1"}
        
        response = self._make_request_with_retry(url, headers=self.headers, params=params)
        if not response:
            # Try with master branch if main doesn't exist
            url = f"{self.base_url}/repos/{repo_full_name}/git/trees/master"
            response = self._make_request_with_retry(url, headers=self.headers, params=params)
        
        if response:
            data = response.json()
            return data.get('tree', [])
        
        return []
    
    def find_dependency_files(self, repo_full_name: str) -> List[str]:
        """Find all dependency files in the repository recursively"""
        dependency_files_found = []
        tree = self.fetch_repository_tree(repo_full_name)
        
        for item in tree:
            if item.get('type') == 'blob':  # Only files, not directories
                file_path = item.get('path', '')
                file_name = os.path.basename(file_path)
                
                if file_name in self.dependency_files:
                    dependency_files_found.append(file_path)
                    logging.debug(f"Found dependency file: {file_path}")
        
        logging.info(f"Found {len(dependency_files_found)} dependency files in {repo_full_name}")
        return dependency_files_found
    
    def download_file(self, repo_full_name: str, file_path: str) -> Optional[str]:
        """Download file contents from GitHub repository"""
        url = f"{self.base_url}/repos/{repo_full_name}/contents/{file_path}"
        
        response = self._make_request_with_retry(url, headers=self.headers)
        if not response:
            return None
        
        try:
            data = response.json()
            if data.get('encoding') == 'base64':
                content = base64.b64decode(data['content']).decode('utf-8')
                return content
            elif 'download_url' in data:
                # Use download_url for larger files
                download_response = self._make_request_with_retry(data['download_url'])
                return download_response.text if download_response else None
        except Exception as e:
            logging.error(f"Error downloading file {file_path} from {repo_full_name}: {e}")
        
        return None
    
    def scan_repositories(self, username: str, vuln_db: VulnerabilityDatabase) -> List[Dict]:
        """Scan all repositories for vulnerabilities with enhanced Slack alerts"""
        repos = self.fetch_repositories(username)
        all_vulnerabilities = []
        
        if not repos:
            logging.warning(f"No repositories found for '{username}'. Check username and token permissions.")
            return all_vulnerabilities
        
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            future_to_repo = {
                executor.submit(self._scan_single_repository, repo, vuln_db): repo 
                for repo in repos
            }
            
            for future in as_completed(future_to_repo):
                repo = future_to_repo[future]
                try:
                    vulnerabilities = future.result()
                    if vulnerabilities:
                        all_vulnerabilities.extend(vulnerabilities)
                        logging.info(f"Found {len(vulnerabilities)} vulnerabilities in {repo['name']}")
                except Exception as e:
                    logging.error(f"Error scanning repository {repo['name']}: {e}")
        
        return all_vulnerabilities
    
    def _scan_single_repository(self, repo: Dict, vuln_db: VulnerabilityDatabase) -> List[Dict]:
        """Scan a single repository for vulnerabilities with recursive file discovery"""
        repo_name = repo['name']
        repo_full_name = repo['full_name']
        vulnerabilities = []
        
        logging.info(f"Scanning repository: {repo_name}")
        
        # Find all dependency files recursively
        dependency_files = self.find_dependency_files(repo_full_name)
        
        if not dependency_files:
            logging.info(f"No dependency files found in {repo_name}")
            return vulnerabilities
        
        # Scan each dependency file found
        for dep_file_path in dependency_files:
            content = self.download_file(repo_full_name, dep_file_path)
            if content:
                logging.debug(f"Downloaded {dep_file_path} from {repo_name}")
                
                # Save file for audit trail
                self._save_dependency_file(repo_name, dep_file_path, content)
                
                # Scan for vulnerabilities
                file_name = os.path.basename(dep_file_path)
                file_vulns = self._scan_dependency_file(content, file_name, vuln_db)
                for vuln in file_vulns:
                    vuln.update({
                        'repository': repo_name,
                        'file': dep_file_path,  # Full path including subdirectories
                        'platform': 'github'
                    })
                vulnerabilities.extend(file_vulns)
        
        return vulnerabilities
    
    def _save_dependency_file(self, repo_name: str, file_path: str, content: str):
        """Save dependency file for audit purposes"""
        if self.config.save_reports:
            base_path = Path("scanned_files") / "github" / repo_name
            base_path.mkdir(parents=True, exist_ok=True)
            
            # Replace path separators for Windows compatibility
            safe_file_path = file_path.replace('/', '_').replace('\\', '_')
            file_save_path = base_path / safe_file_path
            file_save_path.write_text(content, encoding="utf-8")
    
    def _scan_dependency_file(self, content: str, file_type: str, vuln_db: VulnerabilityDatabase) -> List[Dict]:
        """Scan dependency file content for vulnerabilities"""
        vulnerabilities: List[Dict] = []

        try:
            if file_type in ["package.json", "package-lock.json"]:
                vulnerabilities = self._scan_json_dependencies(content, vuln_db)
            elif file_type == "yarn.lock":
                vulnerabilities = self._scan_yarn_lock(content, vuln_db)
            elif file_type == "pnpm-lock.yaml":
                vulnerabilities = self._scan_pnpm_lock(content, vuln_db)
        except Exception as e:
            logging.error(f"Error scanning {file_type}: {e}")

        return vulnerabilities

    def _scan_json_dependencies(self, content: str, vuln_db: VulnerabilityDatabase) -> List[Dict]:
        """Scan package.json and package-lock.json (v1 & v2) dependency files safely."""
        vulnerabilities: List[Dict] = []

        try:
            data = json.loads(content)
            dependencies: Dict[str, object] = {}

            # ---- 1) Normal package.json fields ----
            for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                deps = data.get(key)
                if isinstance(deps, dict):
                    dependencies.update(deps)

            # ---- 2) package-lock.json v1 ----
            lock_deps = data.get("dependencies")
            if isinstance(lock_deps, dict):
                for pkg, info in lock_deps.items():
                    if pkg not in dependencies:
                        dependencies[pkg] = info

            # ---- 3) package-lock.json v2 ----
            lock_pkgs = data.get("packages")
            if isinstance(lock_pkgs, dict):
                for path, info in lock_pkgs.items():
                    if isinstance(info, dict):
                        name = info.get("name")
                        if name and name not in dependencies:
                            dependencies[name] = info

            # ---- 4) Normalize versions & check vuln DB ----
            for package_name, version_info in dependencies.items():
                # version_info can be string or dict
                if isinstance(version_info, dict):
                    version_raw = version_info.get("version") or ""
                else:
                    version_raw = str(version_info)

                if not version_raw:
                    continue

                clean_version = re.sub(r'^[\^~>=<\s]*', '', version_raw)

                package_vulns = vuln_db.is_vulnerable(package_name, clean_version)
                for vuln in package_vulns:
                    vulnerabilities.append({
                        "package": package_name,
                        "version": version_raw,
                        "clean_version": clean_version,
                        "severity": vuln["severity"],
                        "cve_id": vuln.get("cve_id"),
                        "description": vuln.get("description"),
                        "vulnerable_range": vuln["range"],
                    })

        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON in dependency file: {e}")
        except Exception as e:
            logging.error(f"Error scanning JSON dependency file: {e}")

        return vulnerabilities

    def _scan_yarn_lock(self, content: str, vuln_db: VulnerabilityDatabase) -> List[Dict]:
        """Scan yarn.lock files"""
        vulnerabilities = []
        
        try:
            lines = content.splitlines()
            current_package = None
            current_version = None
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    if line.endswith(':') and '@' in line:
                        # Package line
                        package_info = line.rstrip(':')
                        if '@' in package_info:
                            current_package = package_info.split('@')[0]
                    elif line.startswith('version') and current_package:
                        # Version line
                        current_version = line.split('"')[1] if '"' in line else None
                        
                        if current_version:
                            package_vulns = vuln_db.is_vulnerable(current_package, current_version)
                            for vuln in package_vulns:
                                vulnerabilities.append({
                                    'package': current_package,
                                    'version': current_version,
                                    'clean_version': current_version,
                                    'severity': vuln['severity'],
                                    'cve_id': vuln.get('cve_id'),
                                    'description': vuln.get('description'),
                                    'vulnerable_range': vuln['range']
                                })
                        
                        current_package = None
                        current_version = None
        except Exception as e:
            logging.error(f"Error parsing yarn.lock: {e}")
        
        return vulnerabilities
    
    def _scan_pnpm_lock(self, content: str, vuln_db: VulnerabilityDatabase) -> List[Dict]:
        """Scan pnpm-lock.yaml files"""
        vulnerabilities = []
        # Basic YAML parsing for PNPM lock files
        try:
            lines = content.splitlines()
            in_packages_section = False
            
            for line in lines:
                if line.strip() == "packages:":
                    in_packages_section = True
                    continue
                
                if in_packages_section and line.startswith("  /"):
                    # Package definition
                    package_line = line.strip().lstrip("/")
                    if "@" in package_line:
                        parts = package_line.split("@")
                        if len(parts) >= 2:
                            package_name = parts[0]
                            version = parts[1].split(":")[0] if ":" in parts[1] else parts[1]
                            
                            package_vulns = vuln_db.is_vulnerable(package_name, version)
                            for vuln in package_vulns:
                                vulnerabilities.append({
                                    'package': package_name,
                                    'version': version,
                                    'clean_version': version,
                                    'severity': vuln['severity'],
                                    'cve_id': vuln.get('cve_id'),
                                    'description': vuln.get('description'),
                                    'vulnerable_range': vuln['range']
                                })
        except Exception as e:
            logging.error(f"Error parsing pnpm-lock.yaml: {e}")
        
        return vulnerabilities

# ------------------ Enhanced Report Generator ------------------
class ReportGenerator:
    """Enhanced report generation with multiple formats"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def generate_report(self, vulnerabilities: List[Dict], scan_summary: Dict):
        """Generate comprehensive report in specified format"""
        if self.config.report_format.lower() == "json":
            self._generate_json_report(vulnerabilities, scan_summary)
        elif self.config.report_format.lower() == "csv":
            self._generate_csv_report(vulnerabilities, scan_summary)
        elif self.config.report_format.lower() == "html":
            self._generate_html_report(vulnerabilities, scan_summary)
        else:
            self._generate_json_report(vulnerabilities, scan_summary)
    
    def _generate_json_report(self, vulnerabilities: List[Dict], scan_summary: Dict):
        """Generate JSON report"""
        report = {
            "scan_metadata": {
                "timestamp": self.timestamp,
                "tool_version": "NPM3Guard v2.3 - Enhanced Slack Alerts",
                "scan_summary": scan_summary
            },
            "vulnerabilities": vulnerabilities
        }
        
        filename = f"npm3guard_report_{self.timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        logging.info(f"JSON report saved: {filename}")
    
    def _generate_csv_report(self, vulnerabilities: List[Dict], scan_summary: Dict):
        """Generate CSV report"""
        filename = f"npm3guard_report_{self.timestamp}.csv"
        
        if not vulnerabilities:
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["No vulnerabilities found"])
            return
        
        fieldnames = list(vulnerabilities[0].keys())
        
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(vulnerabilities)
        
        logging.info(f"CSV report saved: {filename}")
    
    def _generate_html_report(self, vulnerabilities: List[Dict], scan_summary: Dict):
        """Generate HTML report"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>NPM3Guard Security Report v2.3</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
                .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .summary {{ margin: 20px 0; background-color: white; padding: 15px; border-radius: 5px; }}
                .vulnerability {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; background-color: white; }}
                .high {{ border-left: 5px solid #dc3545; }}
                .medium {{ border-left: 5px solid #ffc107; }}
                .low {{ border-left: 5px solid #28a745; }}
                .critical {{ border-left: 5px solid #721c24; }}
                .file-path {{ font-family: monospace; background-color: #f8f9fa; padding: 2px 4px; border-radius: 3px; }}
                .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
                .stat-box {{ text-align: center; padding: 10px; background-color: white; border-radius: 5px; }}
                .slack-alert {{ background-color: #e8f5e8; padding: 10px; border-radius: 5px; margin: 10px 0; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>NPM3Guard Security Report v2.3</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>✅ Enhanced Slack Alerts + Organization Support + Recursive Scanning</p>
            </div>
            
            <div class="slack-alert">
                <strong>🔔 Enhanced Slack Alerts:</strong> Detailed vulnerability reports are automatically sent to Slack with full breakdown by repository and severity.
            </div>
            
            <div class="stats">
                <div class="stat-box">
                    <h3>{len(vulnerabilities)}</h3>
                    <p>Total Vulnerabilities</p>
                </div>
                <div class="stat-box">
                    <h3>{len([v for v in vulnerabilities if v.get('severity') == 'HIGH'])}</h3>
                    <p>High Severity</p>
                </div>
                <div class="stat-box">
                    <h3>{len([v for v in vulnerabilities if v.get('severity') == 'MEDIUM'])}</h3>
                    <p>Medium Severity</p>
                </div>
                <div class="stat-box">
                    <h3>{len([v for v in vulnerabilities if v.get('severity') == 'LOW'])}</h3>
                    <p>Low Severity</p>
                </div>
            </div>
            
            <div class="summary">
                <h2>Scan Summary</h2>
                <ul>
        """
        
        for key, value in scan_summary.items():
            html_content += f"<li><strong>{key}:</strong> {value}</li>"
        
        html_content += """
                </ul>
            </div>
            
            <div class="vulnerabilities">
                <h2>Vulnerabilities Found</h2>
        """
        
        for vuln in vulnerabilities:
            severity_class = vuln.get('severity', 'low').lower()
            html_content += f"""
                <div class="vulnerability {severity_class}">
                    <h3>{vuln.get('package', 'Unknown Package')}</h3>
                    <p><strong>Version:</strong> {vuln.get('version', 'Unknown')}</p>
                    <p><strong>Severity:</strong> {vuln.get('severity', 'Unknown')}</p>
                    <p><strong>CVE ID:</strong> {vuln.get('cve_id', 'N/A')}</p>
                    <p><strong>Description:</strong> {vuln.get('description', 'No description available')}</p>
                    <p><strong>Repository:</strong> {vuln.get('repository', 'N/A')}</p>
                    <p><strong>File:</strong> <span class="file-path">{vuln.get('file', 'N/A')}</span></p>
                    <p><strong>Platform:</strong> {vuln.get('platform', 'N/A').upper()}</p>
                </div>
            """
        
        html_content += """
            </div>
        </body>
        </html>
        """
        
        filename = f"npm3guard_report_{self.timestamp}.html"
        with open(filename, 'w') as f:
            f.write(html_content)
        
        logging.info(f"HTML report saved: {filename}")

# ------------------ Main NPM3Guard Class ------------------
class NPM3Guard:
    """Main NPM3Guard scanner class with enhanced Slack alerts"""
    
    def __init__(self, config: ScanConfig = None):
        self.config = config or ScanConfig()
        setup_logging(self.config)
        
        self.vuln_db = VulnerabilityDatabase(self.config)
        self.notification_manager = NotificationManager(self.config)
        self.report_generator = ReportGenerator(self.config)
        
        logging.info("NPM3Guard v2.3 initialized with enhanced Slack alerts")
    
    def scan_github(self, username: str, token: str) -> Dict:
        """Scan GitHub repositories with enhanced Slack alerts"""
        logging.info(f"Starting GitHub scan with enhanced alerts for: {username}")
        
        handler = GitHubHandler(token, self.config, self.notification_manager)
        vulnerabilities = handler.scan_repositories(username, self.vuln_db)
        
        scan_summary = {
            "platform": "GitHub",
            "username": username,
            "total_vulnerabilities": len(vulnerabilities),
            "high_severity": len([v for v in vulnerabilities if v.get('severity') == 'HIGH']),
            "medium_severity": len([v for v in vulnerabilities if v.get('severity') == 'MEDIUM']),
            "low_severity": len([v for v in vulnerabilities if v.get('severity') == 'LOW']),
            "scan_time": datetime.now().isoformat(),
            "recursive_scan": self.config.recursive_scan,
            "organization_support": True
        }
        
        # Send detailed Slack alert
        if self.config.detailed_slack_alerts:
            self.notification_manager.send_detailed_scan_alert(scan_summary, vulnerabilities)
        
        if self.config.save_reports:
            self.report_generator.generate_report(vulnerabilities, scan_summary)
        
        return {"vulnerabilities": vulnerabilities, "summary": scan_summary}

# ------------------ CLI Interface ------------------
def create_config_from_args() -> ScanConfig:
    """Create configuration from command line arguments or interactive input"""
    config = ScanConfig()
    
    # Interactive configuration
    print("\n" + "="*75)
    print("NPM3Guard v2.3 Configuration - Enhanced Slack Alerts + Recursive Scanning")
    print("="*75)
    
    # Rate limiting
    rate_limit = input(f"Rate limit delay in seconds (default: {config.rate_limit_delay}): ").strip()
    if rate_limit:
        try:
            config.rate_limit_delay = float(rate_limit)
        except ValueError:
            print("Invalid rate limit, using default")
    
    # Workers
    workers = input(f"Max concurrent workers (default: {config.max_workers}): ").strip()
    if workers:
        try:
            config.max_workers = int(workers)
        except ValueError:
            print("Invalid worker count, using default")
    
    # Report format
    format_choice = input("Report format (json/csv/html) [default: json]: ").strip().lower()
    if format_choice in ['json', 'csv', 'html']:
        config.report_format = format_choice
    
    # Notification webhooks
    slack_webhook = input("Slack webhook URL (optional): ").strip()
    if slack_webhook:
        config.slack_webhook = slack_webhook
        config.detailed_slack_alerts = True
    
    teams_webhook = input("Microsoft Teams webhook URL (optional): ").strip()
    if teams_webhook:
        config.teams_webhook = teams_webhook
    
    return config

def main():
    """Main function with enhanced CLI interface"""
    print(TOOL_NAME)
    
    # Create configuration
    config = create_config_from_args()
    
    # Initialize scanner
    scanner = NPM3Guard(config)
    
    print("\n" + "="*75)
    print("🔔 Enhanced Slack Alerts + GitHub Organization & User Support")
    print("✅ Automatically detects if target is User or Organization")
    print("✅ Recursively scans ALL subfolders for dependency files")
    print("✅ Sends detailed vulnerability reports to Slack with breakdown")
    print("="*75)
    
    username = input("GitHub username/organization (e.g., 'hackerone'): ").strip()
    token = getpass.getpass("GitHub Personal Access Token (ghp_...): ").strip()
    
    if not username:
        print("[!] Username/organization is required")
        return
    
    try:
        print(f"\n[*] Starting GitHub scan for '{username}'...")
        print("[*] Detecting account type (User/Organization)...")
        print("[*] This will scan ALL dependency files in ALL subfolders...")
        
        if config.slack_webhook:
            print("[*] Enhanced Slack alerts are ENABLED - detailed reports will be sent")
        
        result = scanner.scan_github(username, token)
        
        print(f"\n[+] ✅ Scan completed successfully!")
        print(f"[+] Total vulnerabilities found: {result['summary']['total_vulnerabilities']}")
        print(f"[+] High severity: {result['summary']['high_severity']}")
        print(f"[+] Medium severity: {result['summary']['medium_severity']}")
        print(f"[+] Low severity: {result['summary']['low_severity']}")
        
        if result['summary']['total_vulnerabilities'] > 0:
            print(f"\n[!] ⚠️  Vulnerabilities detected! Check the generated reports for details.")
            if config.slack_webhook:
                print(f"[!] 🔔 Detailed Slack alert has been sent with vulnerability breakdown.")
        else:
            print(f"\n[+] 🎉 No vulnerabilities found in the scanned repositories!")
            
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        logging.error(f"Scan failed: {e}")
        print(f"[!] Scan failed: {e}")
    
    print("\n[*] 🔍 NPM3Guard v2.3 scan completed.")
    print("[*] 📁 Check reports and logs for detailed vulnerability information.")
    print("[*] 🔔 Enhanced Slack alerts provide real-time vulnerability notifications.")

if __name__ == "__main__":
    main()
