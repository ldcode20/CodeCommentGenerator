"""
Build benchmarks/realworld/manifest.json from hand-written labels + GHSA metadata.

Labels below were written by reading each advisory and its fix diff (see
benchmarks/README.md, "Labeling protocol"); the security analyzer was not run on
any case before its label was fixed here. Inputs: .benchmarks/ghsa/candidates.json
(produced by benchmarks/fetch.py --discover).
"""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LICENSES = {
    "run-llama/llama_index": "MIT", "geopandas/geopandas": "BSD-3-Clause", "Parsl/parsl": "Apache-2.0",
    "pyload/pyload": "AGPL-3.0 (GitHub: NOASSERTION)", "scitokens/scitokens": "Apache-2.0",
    "blue-yonder/postgraas_server": "Apache-2.0", "nicolargo/glances": "LGPL-3.0 (GitHub: NOASSERTION)",
    "MervinPraison/PraisonAI": "MIT", "piccolo-orm/piccolo": "MIT", "BerriAI/litellm": "NOASSERTION",
    "pgadmin-org/pgadmin4": "PostgreSQL (GitHub: NOASSERTION)", "aws/sagemaker-python-sdk": "Apache-2.0",
    "jelmer/dulwich": "Apache-2.0 OR GPL-2.0+ (GitHub: NOASSERTION)", "PaddlePaddle/Paddle": "Apache-2.0",
    "benbusby/whoogle-search": "MIT", "koxudaxi/datamodel-code-generator": "MIT",
    "ahujasid/blender-mcp": "MIT", "dgtlmoon/changedetection.io": "Apache-2.0",
    "facelessuser/pymdown-extensions": "MIT (GitHub: NOASSERTION)", "eLyiN/gemini-bridge": "MIT",
    "thumbor/thumbor": "MIT", "langchain-ai/langchain-nvidia": "MIT", "lepture/mistune": "BSD-3-Clause",
    "aws/amazon-redshift-python-driver": "Apache-2.0", "agno-agi/agno": "Apache-2.0",
    "icip-cas/PPTAgent": "MIT", "openstack/vitrage": "Apache-2.0 (GitHub: none declared)",
    "torchgeo/torchgeo": "MIT", "django-haystack/django-haystack": "BSD-3-Clause (GitHub: NOASSERTION)",
    "langflow-ai/langflow": "MIT", "xorbitsai/inference": "Apache-2.0", "feast-dev/feast": "Apache-2.0",
    "ray-project/ray": "Apache-2.0", "InternLM/lmdeploy": "Apache-2.0",
    "huggingface/transformers": "Apache-2.0", "explosion/spacy-llm": "MIT", "mlflow/mlflow": "Apache-2.0",
    "Skyvern-AI/skyvern": "AGPL-3.0", "NYUCCL/psiTurk": "MIT", "webcomics/dosage": "MIT",
    "WeblateOrg/wlc": "GPL-3.0", "django-cms/django-cms": "BSD-3-Clause (GitHub: NOASSERTION)",
    "mixxorz/slippers": "MIT",
}

# (ghsa, category, rule, scope, sites{file: (vulnerable_functions, patched_functions)},
#  patched_applicable, why_vulnerable, why_patched)
M, N = "modelled", "api_not_modelled"
LABELS = [
    # ── SQL injection ────────────────────────────────────────────────────
    ("GHSA-339r-cjv9-x78g", "sqli", "SEC005", M,
     {"llama-index-integrations/retrievers/llama-index-retrievers-duckdb-retriever/llama_index/retrievers/duckdb_retriever/base.py":
      (["DuckDBRetriever._retrieve"], ["DuckDBRetriever._retrieve"])}, True,
     "query text interpolated into an f-string SQL statement passed to conn.execute(sql)",
     "query passed as a bound parameter: conn.execute(sql, [query])"),
    ("GHSA-6497-prx7-gpmq", "sqli", "SEC005", M,
     {"geopandas/io/sql.py": (["_write_postgis"], ["_write_postgis"])}, True,
     "schema/table/geometry names interpolated into sqlalchemy text(f\"SELECT Find_SRID(...)\")",
     "text(...).bindparams(...) with named parameters"),
    ("GHSA-f2mf-q878-gh58", "sqli", "SEC005", M,
     {"parsl/monitoring/visualization/views.py": (["workflow_dag_details", "workflow_resources"],
                                                  ["workflow_dag_details", "workflow_resources"])}, True,
     "Flask route parameter workflow_id %-formatted into SQL passed to pandas.read_sql_query",
     "constant SQL with :run_id placeholder and params={...}"),
    ("GHSA-pwh4-6r3m-j2rf", "sqli", "SEC005", M,
     {"src/pyload/core/database/file_database.py": (["FileDatabaseMethods.update_link_info"],
                                                     ["FileDatabaseMethods.update_link_info"])}, True,
     "URLs from the API joined into an IN ('...') clause in an f-string passed to self.c.execute",
     "placeholders '?' built from len(urls); values passed as parameters"),
    ("GHSA-rh5m-2482-966c", "sqli", "SEC005", M,
     {"src/scitokens/utils/keycache.py": (
         ["KeyCache.addkeyinfo", "KeyCache._addkeyinfo", "KeyCache._delete_cache_entry",
          "KeyCache._add_negative_cache_entry", "KeyCache.getkeyinfo"],
         ["KeyCache.addkeyinfo", "KeyCache._addkeyinfo", "KeyCache._delete_cache_entry",
          "KeyCache._add_negative_cache_entry", "KeyCache.getkeyinfo"])}, True,
     "issuer/key_id .format()-ed into DELETE/INSERT/SELECT statements passed to curs.execute",
     "statements use ? placeholders with parameter lists"),
    ("GHSA-vghm-8cjp-hjw6", "sqli", "SEC005", M,
     {"postgraas_server/backends/postgres_cluster/postgres_cluster_driver.py": (
         ["check_db_or_user_exists", "create_postgres_db"], ["check_db_or_user_exists", "create_postgres_db"])},
     True, "db_name/db_user .format()-ed into SQL passed to cur.execute",
     "%s parameters and psycopg2.sql.SQL/Identifier composition"),
    ("GHSA-x46r-mf5g-xpr6", "sqli", "SEC005", M,
     {"glances/exports/glances_timescaledb/__init__.py": (["Export.export"], ["Export.export"])}, True,
     "process names / plugin names quoted into f-string INSERT/CREATE statements passed to cur.execute",
     "psycopg sql.SQL composition with sql.Identifier and executemany placeholders"),
    ("GHSA-x783-xp3g-mqhp", "sqli", "SEC005", M,
     {"src/praisonai/praisonai/persistence/conversation/sqlite.py": (
         ["SQLiteConversationStore._create_tables", "SQLiteConversationStore.create_session",
          "SQLiteConversationStore.get_session", "SQLiteConversationStore.update_session",
          "SQLiteConversationStore.delete_session", "SQLiteConversationStore.list_sessions",
          "SQLiteConversationStore.add_message"],
         ["SQLiteConversationStore._create_tables", "SQLiteConversationStore.create_session",
          "SQLiteConversationStore.get_session", "SQLiteConversationStore.update_session",
          "SQLiteConversationStore.delete_session", "SQLiteConversationStore.list_sessions",
          "SQLiteConversationStore.add_message"])}, True,
     "constructor table_prefix stored in table-name fields interpolated into f-string SQL",
     "__init__ rejects table_prefix unless re.match(r'^[a-zA-Z0-9_]*$', ...) before storing it"),
    ("GHSA-xq59-7jf3-rjc6", "sqli", "SEC005", M,
     {"piccolo/engine/postgres.py": (["Savepoint.rollback_to", "Savepoint.release", "PostgresTransaction.savepoint"],
                                     ["Savepoint.rollback_to", "Savepoint.release", "PostgresTransaction.savepoint"]),
      "piccolo/engine/sqlite.py": (["Savepoint.rollback_to", "Savepoint.release", "SQLiteTransaction.savepoint"],
                                   ["Savepoint.rollback_to", "Savepoint.release", "SQLiteTransaction.savepoint"])},
     True, "savepoint name interpolated into f\"SAVEPOINT {name}\" passed to connection.execute",
     "validate_savepoint_name() (imported helper that raises) is called before each statement"),
    ("GHSA-h6m6-jj8v-94jj", "sqli", "SEC005", N,
     {"litellm/proxy/proxy_server.py": (["global_spend_logs"], ["global_spend_logs"])}, True,
     "api_key concatenated into SQL passed to prisma_client.db.query_raw (Prisma API, not modelled)",
     "query_raw with $1 placeholder"),
    ("GHSA-hp84-p2gq-6fvr", "sqli", "SEC005", N,
     {"web/pgadmin/tools/maintenance/__init__.py": (["create_maintenance_job"], ["create_maintenance_job"])}, True,
     "user option values rendered into a SQL template (render_template) that is executed later (not modelled)",
     "values allow-listed by validate_maintenance_data before rendering"),
    # ── Command injection ────────────────────────────────────────────────
    ("GHSA-7pc3-pr3q-58vg", "cmdi", "SEC002", M,
     {"src/sagemaker/serve/save_retrive/version_1_0_0/save/utils.py": (["capture_dependencies"], ["capture_dependencies"])},
     True, "requirements path interpolated into an f-string passed to os.system",
     "argument list passed to subprocess.run without a shell"),
    ("GHSA-9277-mp7x-85jf", "cmdi", "SEC002", M,
     {"dulwich/merge_drivers.py": (["ProcessMergeDriver.merge"], ["ProcessMergeDriver.merge"])}, True,
     "file path (%P) substituted into a command run with subprocess.run(cmd, shell=True)",
     "every substituted value passes through _shell_quote (shlex.quote / cmd.exe quoting)"),
    ("GHSA-g99h-56mw-8263", "cmdi", "SEC002", M,
     {"llama-index-cli/llama_index/cli/rag/base.py": (["RagCLI.handle_cli"], ["RagCLI.handle_cli"])}, True,
     "--files path joined into a command string executed with os.system",
     "path quoted with shlex.quote"),
    ("GHSA-j5h9-9r39-43q5", "cmdi", "SEC002", M,
     {"python/paddle/incubate/distributed/fleet/fleet_util.py": (["FleetUtil.get_online_pass_interval"],
                                                                 ["FleetUtil.get_online_pass_interval"])}, True,
     "days/hours parameters concatenated into os.popen(\"echo -n \" + days)",
     "assert statements reject shell metacharacters before os.popen"),
    ("GHSA-rf7p-79xq-8xwm", "cmdi", "SEC002", M,
     {"python/paddle/utils/download.py": (["_wget_download"], ["_wget_download"])}, False,
     "url and file name interpolated into a wget command run with Popen(shell=True)",
     "NOT fixed by this commit: it only adds an http/https scheme assert; url and fullname stay "
     "unquoted in the shell command (re-reported as GHSA-qqv2-35q8-p2g2). Label corrected, see "
     "LABEL_CORRECTIONS"),
    ("GHSA-rm79-x4g6-hvg5", "cmdi", "SEC002", M,
     {"web/pgadmin/misc/bgprocess/process_executor.py": (["execute"], ["execute"])}, True,
     "Popen(cmd, **kwargs) with kwargs['shell'] = True on Windows",
     "kwargs['shell'] = False"),
    # ── Code injection ───────────────────────────────────────────────────
    ("GHSA-3cr5-2446-8pg3", "codeinj", "SEC001", M,
     {"python/paddle/jit/dy2static/convert_operators.py": (["convert_shape_compare"], [])}, False,
     "comparison operator string from *args concatenated into eval()",
     "function removed by the fix (no patched counterpart)"),
    ("GHSA-29h4-r29x-hchv", "codeinj", "SEC001", M,
     {"redshift_connector/utils/type_utils.py": (["vector_in"], ["vector_in"])}, True,
     "server-supplied bytes decoded and passed to eval()", "parsed with int() over split()"),
    ("GHSA-77rh-m34w-rv36", "codeinj", "SEC001", M,
     {"libs/agno/agno/models/base.py": (["Model.run_function_calls", "Model.arun_function_calls"],
                                        ["Model.run_function_calls", "Model.arun_function_calls"]),
      "libs/agno/agno/tools/function.py": (["UserInputField.from_dict"], ["UserInputField.from_dict"])}, True,
     "field_type string from tool/user data passed to eval()", "mapped through a fixed type dictionary"),
    ("GHSA-89g2-xw5c-v95p", "codeinj", "SEC001", M,
     {"pptagent/apis.py": (["CodeExecutor.execute_actions"], ["CodeExecutor.execute_actions"])}, True,
     "LLM-generated code line passed to eval(line, {}, ...) with default builtins",
     "eval with globals {'__builtins__': {}} (advisory considers this fixed)"),
    ("GHSA-8xwf-cr4r-856r", "codeinj", "SEC001", M,
     {"vitrage/graph/query.py": (["create_predicate"], ["create_predicate"])}, True,
     "query dictionary turned into an expression string passed to eval()",
     "predicate built from operator functions without eval"),
    ("GHSA-ghq9-vc6f-8qjf", "codeinj", "SEC001", M,
     {"torchgeo/models/api.py": (["get_weight"], ["get_weight"])}, True,
     "weight name passed to eval(name)", "name looked up in the registered weights mapping"),
    ("GHSA-r3hx-x5rh-p9vv", "codeinj", "SEC001", M,
     {"haystack/backends/elasticsearch_backend.py": (["ElasticsearchSearchBackend._to_python"],
                                                     ["ElasticsearchSearchBackend._to_python"])}, True,
     "Elasticsearch result value passed to eval()", "ast.literal_eval"),
    ("GHSA-v798-mcc6-2m3m", "codeinj", "SEC001", M,
     {"src/lfx/src/lfx/custom/validate.py": (["validate_code"], ["validate_code"])}, True,
     "submitted code compiled and exec()-ed while 'validating'", "code is only compiled, not executed"),
    ("GHSA-x2rj-828p-hx9m", "codeinj", "SEC001", M,
     {"xinference/model/llm/tool_parsers/llama3_tool_parser.py": (["Llama3ToolParser.extract_tool_calls"],
                                                                  ["Llama3ToolParser.extract_tool_calls"]),
      "xinference/model/llm/utils.py": (["ChatModelMixin._eval_llama3_chat_arguments"],
                                        ["ChatModelMixin._eval_llama3_chat_arguments"])}, True,
     "model output passed to eval(text, {}, {})", "json.loads / ast.literal_eval"),
    # ── Deserialization ──────────────────────────────────────────────────
    ("GHSA-2689-cw26-6cpj", "deserialization", "SEC009", M,
     {"app/models/config.py": (["Config._decode_preferences"], ["Config._decode_preferences"])}, True,
     "user-supplied preferences token decompressed and passed to pickle.loads (advisory CWE-78; mechanism is CWE-502)",
     "preferences decoded with json.loads"),
    ("GHSA-34wm-4hw7-qfjv", "deserialization", "SEC010", M,
     {"sdk/python/feast/infra/compute_engines/kubernetes/main.py": (["<module>"], ["<module>"])}, True,
     "configuration file / base64 payload loaded with yaml.load(..., Loader=yaml.Loader)", "yaml.safe_load"),
    ("GHSA-hhrp-gw25-jr43", "deserialization", "SEC009", M,
     {"python/ray/data/_internal/datasource/webdataset_datasource.py": (["_default_decoder"], ["_default_decoder"])},
     True, "dataset sample bytes for .pyd/.pickle keys passed to pickle.loads",
     "pickle.loads only when allow_unsafe=True (default False) is passed by the caller"),
    ("GHSA-2vh9-42vm-xmv2", "deserialization", "SEC009", N,
     {"lmdeploy/pytorch/disagg/conn/engine_conn.py": (["EngineP2PConnection.handle_zmq_recv"],
                                                      ["EngineP2PConnection.handle_zmq_recv"])}, True,
     "zmq recv_pyobj() (pickle) on network input (API not modelled)", "recv_json + pydantic validation"),
    ("GHSA-69w3-r845-3855", "deserialization", "SEC009", N,
     {"src/transformers/trainer.py": (["Trainer._load_rng_state"], ["Trainer._load_rng_state"])}, True,
     "torch.load(rng_file) without weights_only (API not modelled)", "torch.load(..., weights_only=True)"),
    # ── Path traversal ───────────────────────────────────────────────────
    ("GHSA-442q-2j6p-642g", "pathtraver", "SEC013", M,
     {"src/datamodel_code_generator/parser/xmlschema.py": (["_XMLSchemaConverter._collect_schema"],
                                                           ["_XMLSchemaConverter._collect_schema"])}, True,
     "schemaLocation from the input document resolved relative to the source directory and read",
     "_resolve_schema_location requires location.is_relative_to(base_path)"),
    ("GHSA-4h8q-hh2j-755w", "pathtraver", "SEC013", M,
     {"addon.py": (["BlenderMCPServer.download_polyhaven_asset"], ["BlenderMCPServer.download_polyhaven_asset"])},
     True, "include path from remote asset metadata joined to temp_dir and written with open(..., 'wb')",
     "abspath + startswith(abs_temp_dir + os.sep) check, '..' and absolute paths skipped"),
    ("GHSA-5jmr-gcrj-2c9q", "pathtraver", "SEC013", M,
     {"litellm/llms/litellm_proxy/skills/sandbox_executor.py": (["SkillsSandboxExecutor.execute"],
                                                                ["SkillsSandboxExecutor.execute"])}, True,
     "archive member names used as paths for open(local_path, 'wb')",
     "member paths normalised and rejected if they start with '..' or are absolute"),
    ("GHSA-9xwg-3r6f-jcx2", "pathtraver", "SEC013", M,
     {"pymdownx/b64.py": (["repl_path"], ["repl_path"])}, True,
     "<img src> path from Markdown joined to base_path and opened",
     "abspath + startswith(root_path + os.sep) restriction"),
    ("GHSA-c5px-58j2-7fqp", "pathtraver", "SEC013", M,
     {"src/mcp_server.py": (["_prepare_inline_payload", "_resolve_path"], ["_prepare_inline_payload", "_resolve_path"])},
     True, "MCP tool file arguments resolved without containment and read",
     "resolved candidate must stay under the resolved directory root"),
    ("GHSA-cj54-hpcc-gj6h", "pathtraver", "SEC013", M,
     {"thumbor/loaders/file_loader.py": (["load"], ["load"])}, True,
     "request path joined to FILE_LOADER_ROOT_PATH and opened", "commonpath containment check"),
    ("GHSA-g28h-2cmm-rj9x", "pathtraver", "SEC013", M,
     {"libs/ai-endpoints/langchain_nvidia_ai_endpoints/_utils.py": (["_url_to_b64_string"], ["_url_to_b64_string"])},
     True, "image_source string opened as a local file when it exists", "local file branch removed"),
    ("GHSA-h7ww-273w-6cm8", "pathtraver", "SEC013", M,
     {"src/mistune/directives/include.py": (["Include.parse"], ["Include.parse"])}, True,
     "include directive path joined to the source directory and opened",
     "realpath + commonpath containment, absolute paths rejected"),
    ("GHSA-9jj8-v89v-xjvw", "pathtraver", "SEC013", N,
     {"changedetectionio/flask_app.py": (["changedetection_app.static_content"],
                                         ["changedetection_app.static_content"])}, True,
     "route parameter (dots allowed) used as the *directory* argument of send_from_directory (not modelled)",
     "group/filename reduced to [a-z0-9_]"),
    # ── Template injection ───────────────────────────────────────────────
    ("GHSA-793v-gxfp-9q9h", "ssti", "SEC015", M,
     {"spacy_llm/tasks/builtin_task.py": (["BuiltinTask.generate_prompts"], ["BuiltinTask.generate_prompts"])},
     True, "user-configured template compiled with jinja2.Environment().from_string",
     "jinja2.sandbox.SandboxedEnvironment"),
    ("GHSA-cxfr-5q3r-2rc2", "ssti", "SEC015", M,
     {"mlflow/recipes/cards/__init__.py": (["CardTab.to_html"], ["CardTab.to_html"])}, True,
     "card template compiled with jinja2.Environment(...).from_string", "SandboxedEnvironment"),
    ("GHSA-h92g-3xc3-ww2r", "ssti", "SEC015", M,
     {"skyvern/forge/sdk/workflow/models/block.py": (
         ["Block.format_block_parameter_template_from_workflow_run_context"],
         ["Block.format_block_parameter_template_from_workflow_run_context"])}, True,
     "workflow parameter compiled with jinja2.Template", "SandboxedEnvironment().from_string"),
    ("GHSA-9mq4-9556-6qxq", "ssti", "SEC015", M,
     {"psiturk/experiment.py": (["advertisement", "give_consent"], ["advertisement", "give_consent"])}, True,
     "request argument 'mode' concatenated into page HTML rendered with render_template_string",
     "mode passed as a template variable ({{ mode }})"),
    # ── XSS (all HTML-string renderers; sink kind not modelled) ─────────
    ("GHSA-58cw-g322-p94v", "xss", "SEC014", N,
     {"src/mistune/directives/image.py": (["render_figure"], ["render_figure"]),
      "src/mistune/directives/admonition.py": (["render_admonition"], ["render_admonition"])}, True,
     "directive options concatenated into returned HTML", "escape_text()"),
    ("GHSA-6269-cqxg-mhhv", "xss", "SEC014", N,
     {"src/mistune/toc.py": (["render_toc_ul"], ["render_toc_ul"])}, True,
     "heading id formatted into <a href> in returned HTML", "escape(k)"),
    ("GHSA-75mw-h36v-2jv7", "xss", "SEC014", N,
     {"dosagelib/events.py": (["HtmlEventHandler.comicDownloaded", "RSSEventHandler.comicDownloaded"],
                              ["HtmlEventHandler.comicDownloaded", "RSSEventHandler.comicDownloaded"])}, True,
     "remote comic text written into HTML/RSS output", "html.escape"),
    ("GHSA-gx2m-mcc2-r4p3", "xss", "SEC014", N,
     {"wlc/main.py": (["Command.print_html"], ["Command.print_html"])}, True,
     "API values printed into an HTML table", "html.escape via format_html_value"),
    ("GHSA-hvq6-2r72-p2x7", "xss", "SEC014", N,
     {"cms/plugin_rendering.py": (["ContentRenderer.render_exception"], ["ContentRenderer.render_exception"])},
     True, "exception message interpolated into an HTML heading", "django format_html"),
    ("GHSA-w7rv-gfp4-j9j3", "xss", "SEC014", N,
     {"slippers/templatetags/slippers.py": (["attr_string"], ["attr_string"])}, True,
     "attribute value interpolated into key=\"value\" markup", "django format_html"),
]

# Corrections made after the initial labelling, with the evidence used (never analyzer output alone).
LABEL_CORRECTIONS = {
    "GHSA-rf7p-79xq-8xwm": "patched revision originally labelled safe ('both values wrapped in "
                           "shlex.quote'), which described the *later* code shown in GHSA-qqv2's "
                           "diff. Re-reading the fix commit's file shows only a scheme assert; the "
                           "patched side is therefore not a valid negative and is excluded "
                           "(patched_applicable=False). Re-inspection was prompted by an analyzer "
                           "finding on the patched file; the corrected label rests on the source "
                           "text and advisory GHSA-qqv2-35q8-p2g2.",
}

EXCLUDED = {
    "GHSA-4h97-wpxp-3757": "SQL assembled in query-builder helpers and executed via objects elsewhere; site not attributable",
    "GHSA-7p73-8jqx-23r8": "duplicate of GHSA-4h97 (same fix commit)",
    "GHSA-v3c8-3pr6-gr7p": "referenced commit does not contain the SQL fix",
    "GHSA-7gj6-22m4-qfhx": "feature executes user SQL by design; fix is a keyword blocklist",
    "GHSA-pmch-g965-grmr": "blocklist on intentionally executed SQL",
    "GHSA-92qf-8gh3-gwcm": "configuration-only change",
    "GHSA-gvg8-93h5-g6qq": "ORM-internal alias validation regex",
    "GHSA-mwm9-4648-f68q": "ORM-internal type check",
    "GHSA-hgjp-83m4-h4fj": "DB driver internal escaping",
    "GHSA-v9hf-5j83-6xpp": "DB driver internal escaping",
    "GHSA-xxh2-68g9-8jqr": "SQLAlchemy expression API (no SQL text)",
    "GHSA-7587-9684-52r6": "Databricks SDK statement API",
    "GHSA-9gm9-c8mq-vq7m": "command executed in another module",
    "GHSA-9qhq-v63v-fv3j": "duplicate of GHSA-9gm9",
    "GHSA-rvhj-8chj-8v3c": "command string executed in another module",
    "GHSA-v5gf-r78h-55q6": "templates rendered in another module",
    "GHSA-w584-2h2r-2hvf": "duplicate fix of GHSA-v798",
    "GHSA-r4rv-85jg-w4mf": "duplicate fix of GHSA-h7ww",
    "GHSA-g97x-gvcm-x72h": "duplicate fix of GHSA-58cw",
}


def split_of(repo: str) -> str:
    """Projects (not cases) are split so one codebase never appears in both sets."""
    return "heldout" if int(hashlib.sha256(repo.encode()).hexdigest(), 16) % 2 == 0 else "dev"


def main(candidates_path: str) -> None:
    cands = {c["ghsa"]: c for c in json.load(open(candidates_path, encoding="utf-8"))}
    cases = []
    for gid, cat, rule, scope, sites, patched_ok, why_v, why_p in LABELS:
        c = cands[gid]
        cases.append({
            "id": gid, "cve": c.get("cve"), "advisory_cwes": c["cwes"], "package": c["package"],
            "summary": c["summary"], "repo": c["repo"], "license": LICENSES[c["repo"]],
            "vulnerable_commit": c["vulnerable_commit"], "fix_commit": c["fix_commit"],
            "category": cat, "rule": rule, "scope": scope, "split": split_of(c["repo"]),
            "sites": [{"file": f, "vulnerable_functions": v, "patched_functions": p}
                      for f, (v, p) in sites.items()],
            "patched_applicable": patched_ok,
            "why_vulnerable": why_v, "why_patched_safe": why_p,
            "label_source": "manual reading of advisory + fix diff; not derived from analyzer output",
            "independent_review": False,
        })
    out = {"dataset": "GHSA real-world fix pairs", "version": "2026-10-26",
           "selection": "reviewed pip advisories for CWE-89/78/22/79/94/95/502/1336 with exactly one "
                        "GitHub fix commit touching <=3 non-test .py files and <=80 changed lines; "
                        "first in-scope cases in GHSA-ID order per category",
           "cases": cases, "excluded": EXCLUDED, "label_corrections": LABEL_CORRECTIONS}
    json.dump(out, open(os.path.join(HERE, "manifest.json"), "w", encoding="utf-8"), indent=1)
    by = {}
    for c in cases:
        by.setdefault((c["split"], c["scope"]), 0)
        by[(c["split"], c["scope"])] += 1
    print(len(cases), "cases", by)


if __name__ == "__main__":
    main(sys.argv[1])
