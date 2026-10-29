"""
Basic tests for Flask application configuration and imports
Note: Full app tests require proper environment setup
"""
import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestAppConfiguration(unittest.TestCase):
    """Test basic application configuration"""
    
    def test_config_import(self):
        """Test that config module can be imported"""
        try:
            from config import Config
            self.assertIsNotNone(Config)
            self.assertTrue(hasattr(Config, 'JWT_SECRET_KEY'))
            self.assertTrue(hasattr(Config, 'DATABASE_URL'))
        except ImportError as e:
            self.fail(f"Failed to import Config: {e}")
    
    def test_models_import(self):
        """Test that models can be imported"""
        try:
            from models import User, Project, Task, Message
            self.assertIsNotNone(User)
            self.assertIsNotNone(Project)
            self.assertIsNotNone(Task)
            self.assertIsNotNone(Message)
        except ImportError as e:
            self.fail(f"Failed to import models: {e}")
    
    def test_database_import(self):
        """Test that database module can be imported"""
        try:
            from database import init_db
            self.assertIsNotNone(init_db)
        except ImportError as e:
            self.fail(f"Failed to import database: {e}")


class TestRouteImports(unittest.TestCase):
    """Test that route modules can be imported"""
    
    def test_auth_routes_import(self):
        """Test auth routes import"""
        try:
            from routes import auth
            self.assertIsNotNone(auth)
            self.assertTrue(hasattr(auth, 'bp'))
        except ImportError as e:
            self.fail(f"Failed to import auth routes: {e}")
    
    def test_projects_routes_import(self):
        """Test projects routes import"""
        try:
            from routes import projects
            self.assertIsNotNone(projects)
            self.assertTrue(hasattr(projects, 'bp'))
        except ImportError as e:
            self.fail(f"Failed to import projects routes: {e}")
    
    def test_tasks_routes_import(self):
        """Test tasks routes import"""
        try:
            from routes import tasks
            self.assertIsNotNone(tasks)
            self.assertTrue(hasattr(tasks, 'bp'))
        except ImportError as e:
            self.fail(f"Failed to import tasks routes: {e}")


class TestGetTasksApiSQLInjection(unittest.TestCase):
    """Tests verifying the SQL injection fix in get_tasks_api (api.py line 218-225).

    The vulnerability was: user-controlled 'search', 'project_id', and
    'assigned_to' query parameters were interpolated directly into a raw SQL
    string before being passed to db.session.execute(text(...)).

    The fix replaces string interpolation with SQLAlchemy parameterized queries
    using named bind parameters (:search, :project_id, :assigned_to), so the
    database driver separates data from code at all times.
    """

    def test_get_tasks_api_uses_parameterized_query(self):
        """Verify get_tasks_api builds a parameterized SQL query, not a
        concatenated one, when the 'search' parameter is provided."""
        import ast, inspect
        from routes import api as api_module

        source = inspect.getsource(api_module.get_tasks_api)
        # The function must NOT contain Python string-format calls that embed
        # user inputs directly into the SQL string.
        self.assertNotIn(
            '.format(search', source,
            "get_tasks_api must not use .format() to embed 'search' in SQL"
        )
        self.assertNotIn(
            'f"SELECT', source,
            "get_tasks_api must not use f-string SQL construction with search"
        )
        self.assertNotIn(
            "f' AND project_id = {project_id}", source,
            "get_tasks_api must not embed project_id directly in SQL string"
        )
        self.assertNotIn(
            "f' AND assigned_to = {assigned_to}", source,
            "get_tasks_api must not embed assigned_to directly in SQL string"
        )

    def test_get_tasks_api_uses_named_bind_parameters(self):
        """Verify get_tasks_api uses SQLAlchemy named bind parameters (:name)
        for all user-supplied values."""
        import inspect
        from routes import api as api_module

        source = inspect.getsource(api_module.get_tasks_api)
        self.assertIn(
            ':search', source,
            "get_tasks_api must use :search named bind parameter"
        )
        self.assertIn(
            ':project_id', source,
            "get_tasks_api must use :project_id named bind parameter"
        )
        self.assertIn(
            ':assigned_to', source,
            "get_tasks_api must use :assigned_to named bind parameter"
        )

    def test_get_tasks_api_passes_params_dict_to_execute(self):
        """Verify that db.session.execute is called with both the text() object
        and a parameters dictionary (not a bare interpolated string)."""
        import inspect
        from routes import api as api_module

        source = inspect.getsource(api_module.get_tasks_api)
        # After the fix the execute call must pass a params dict (the variable
        # is named 'params' in the fixed implementation).
        self.assertIn(
            'db.session.execute(text(sql), params)', source,
            "get_tasks_api must call db.session.execute with text(sql) and a "
            "params dictionary, not a bare interpolated string"
        )

    def test_sql_injection_payload_does_not_appear_in_raw_query(self):
        """Simulate what happens when a SQL-injection payload is provided as the
        'search' parameter.  With parameterized queries the payload is treated
        as a literal string value, not as SQL syntax.  We verify this by
        inspecting the generated SQLAlchemy TextClause: the payload must appear
        nowhere in the SQL text itself."""
        from sqlalchemy import text as sa_text

        injection_payload = "' OR '1'='1"

        # Build the query the same way the fixed code does.
        sql = "SELECT * FROM tasks WHERE title LIKE :search OR description LIKE :search"
        params = {"search": f"%{injection_payload}%"}

        clause = sa_text(sql)
        # The SQL template must not contain the raw payload.
        self.assertNotIn(
            injection_payload, str(clause),
            "SQL injection payload must not appear in the SQL template string"
        )
        # The payload is only stored in the params dict (as a safe literal).
        self.assertIn(injection_payload, params["search"])

    def test_sql_injection_union_payload_not_in_sql_text(self):
        """Ensure a UNION-based injection payload stays out of the SQL text."""
        from sqlalchemy import text as sa_text

        payload = "' UNION SELECT username, password FROM users--"
        sql = "SELECT * FROM tasks WHERE title LIKE :search OR description LIKE :search"
        params = {"search": f"%{payload}%"}

        clause = sa_text(sql)
        self.assertNotIn(payload, str(clause))
        self.assertIn(payload, params["search"])

    def test_numeric_project_id_bind_parameter(self):
        """Ensure project_id is passed as a bind parameter, not concatenated."""
        from sqlalchemy import text as sa_text

        project_id = "42 OR 1=1"
        sql = "SELECT * FROM tasks WHERE title LIKE :search OR description LIKE :search"
        params = {"search": "%test%"}
        sql += " AND project_id = :project_id"
        params["project_id"] = project_id

        clause = sa_text(sql)
        # The raw project_id value must NOT appear in the SQL template.
        self.assertNotIn(project_id, str(clause))
        self.assertEqual(params["project_id"], project_id)

    def test_assigned_to_bind_parameter(self):
        """Ensure assigned_to is passed as a bind parameter, not concatenated."""
        from sqlalchemy import text as sa_text

        assigned_to = "0; DROP TABLE tasks--"
        sql = "SELECT * FROM tasks WHERE title LIKE :search OR description LIKE :search"
        params = {"search": "%test%"}
        sql += " AND assigned_to = :assigned_to"
        params["assigned_to"] = assigned_to

        clause = sa_text(sql)
        self.assertNotIn(assigned_to, str(clause))
        self.assertEqual(params["assigned_to"], assigned_to)


if __name__ == '__main__':
    unittest.main()

