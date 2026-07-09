import unittest

from audit_agent.dataflow import engine
from audit_agent.dataflow.ir import SanitizerNode, SinkNode, SourceNode
from audit_agent.dataflow.python_frontend import PythonDataflowFrontend


class DataflowEngineTests(unittest.TestCase):
    def test_python_same_file_helper_return_adds_explicit_return_step(self):
        text = "\n".join(
            [
                "from flask import request",
                "",
                "def build_query(name):",
                "    return \"select * from users where name='%s'\" % name",
                "",
                "@app.route('/user')",
                "def user():",
                "    name = request.args.get('name')",
                "    cursor.execute(build_query(name))",
            ]
        )

        traces = PythonDataflowFrontend().analyze("app.py", text)

        self.assertEqual(1, len(traces))
        self.assertIn("helper-return", [step.step_type for step in traces[0].steps])
        self.assertTrue(any("build_query" in step.expression for step in traces[0].steps))

    def test_python_helper_argument_not_returned_is_no_flow(self):
        text = "\n".join(
            [
                "from flask import request",
                "",
                "def constant_query(name):",
                "    return 'select * from users where active=1'",
                "",
                "@app.route('/user')",
                "def user():",
                "    name = request.args.get('name')",
                "    cursor.execute(constant_query(name))",
            ]
        )

        traces = PythonDataflowFrontend().analyze("app.py", text)

        self.assertEqual([], traces)

    def test_engine_classifies_sink_only_without_promoting_to_complete_flow(self):
        classify = getattr(engine, "classify_flow_status", None)
        self.assertIsNotNone(classify)
        sink = SinkNode(
            path="app.py",
            start_line=10,
            end_line=10,
            expression="cursor.execute(query)",
            language="python",
            sink_type="sql",
            vulnerability_class="sql-injection",
        )

        status = classify(source=None, sink=sink, sanitizers=[])

        self.assertEqual("sink-only", status)

    def test_engine_classifies_no_flow_when_sink_is_absent(self):
        classify = getattr(engine, "classify_flow_status", None)
        self.assertIsNotNone(classify)
        source = SourceNode(
            path="app.py",
            start_line=8,
            end_line=8,
            expression="request.args.get('name')",
            language="python",
            symbol="name",
        )
        sanitizer = SanitizerNode(
            path="app.py",
            start_line=9,
            end_line=9,
            expression="name in allowed",
            language="python",
            symbol="name",
        )

        status = classify(source=source, sink=None, sanitizers=[sanitizer])

        self.assertEqual("no-flow", status)


if __name__ == "__main__":
    unittest.main()
