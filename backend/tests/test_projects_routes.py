"""
Tests for project routes — with emphasis on the authorization fix for CWE-639
(Authorization Bypass Through User-Controlled Key) in get_project_dashboard.

Uses the pytest fixtures defined in conftest.py.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import db, User, Project, Task, Document
from auth import generate_token


# ---------------------------------------------------------------------------
# Helper fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def other_user(db_session):
    """A second, unrelated authenticated user."""
    user = User(
        username='otheruser',
        email='other@example.com',
        role='team_member',
    )
    user.set_password('password456')
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def other_auth_headers(app, other_user):
    """JWT headers for the unrelated user."""
    with app.app_context():
        token = generate_token(other_user.id, other_user.username)
        return {'Authorization': f'Bearer {token}'}


@pytest.fixture
def private_project(db_session, sample_user):
    """A private project owned by sample_user."""
    project = Project(
        name='Private Project',
        description='Confidential project',
        owner_id=sample_user.id,
        is_public=False,
    )
    db_session.add(project)
    db_session.commit()
    return project


@pytest.fixture
def public_project(db_session, sample_user):
    """A public project owned by sample_user."""
    project = Project(
        name='Public Project',
        description='Open project',
        owner_id=sample_user.id,
        is_public=True,
    )
    db_session.add(project)
    db_session.commit()
    return project


@pytest.fixture
def project_with_data(db_session, private_project, sample_user):
    """A private project that has tasks and documents."""
    task = Task(
        title='Dashboard Task',
        description='Task for dashboard test',
        project_id=private_project.id,
        created_by=sample_user.id,
        status='pending',
        priority='medium',
    )
    doc = Document(
        filename='report.pdf',
        original_filename='report.pdf',
        file_path='/uploads/report.pdf',
        file_size=1024,
        file_type='application/pdf',
        project_id=private_project.id,
        uploaded_by=sample_user.id,
        is_public=False,
    )
    db_session.add(task)
    db_session.add(doc)
    db_session.commit()
    return private_project


# ---------------------------------------------------------------------------
# Dashboard — authorization checks (CWE-639 remediation)
# ---------------------------------------------------------------------------

class TestProjectDashboardAuthorization:
    """
    Verify that the dashboard endpoint enforces ownership/role checks and
    does NOT allow arbitrary authenticated users to access private projects
    by supplying a user-controlled project_id.
    """

    def test_owner_can_access_own_private_dashboard(
        self, client, project_with_data, auth_headers
    ):
        """Project owner must be able to see the dashboard of their own project."""
        resp = client.get(
            f'/api/projects/{project_with_data.id}/dashboard',
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'project' in data
        assert 'tasks' in data
        assert 'documents' in data
        assert 'stats' in data

    def test_unrelated_user_cannot_access_private_dashboard(
        self, client, private_project, other_auth_headers
    ):
        """
        Core regression test for CWE-639.
        An authenticated user who does NOT own a private project must receive
        403, not project data.
        """
        resp = client.get(
            f'/api/projects/{private_project.id}/dashboard',
            headers=other_auth_headers,
        )
        assert resp.status_code == 403
        data = resp.get_json()
        assert 'error' in data
        # Must not leak project data
        assert 'project' not in data
        assert 'tasks' not in data
        assert 'documents' not in data

    def test_admin_can_access_any_private_dashboard(
        self, client, private_project, admin_auth_headers
    ):
        """Admins must be able to access any project dashboard."""
        resp = client.get(
            f'/api/projects/{private_project.id}/dashboard',
            headers=admin_auth_headers,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'project' in data

    def test_any_authenticated_user_can_access_public_dashboard(
        self, client, public_project, other_auth_headers
    ):
        """Public projects should be accessible to any authenticated user."""
        resp = client.get(
            f'/api/projects/{public_project.id}/dashboard',
            headers=other_auth_headers,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'project' in data

    def test_unauthenticated_request_is_rejected(self, client, private_project):
        """Requests without a valid token must be rejected (401)."""
        resp = client.get(f'/api/projects/{private_project.id}/dashboard')
        assert resp.status_code == 401

    def test_nonexistent_project_returns_404(self, client, auth_headers):
        """A request for a project that doesn't exist must return 404."""
        resp = client.get('/api/projects/999999/dashboard', headers=auth_headers)
        assert resp.status_code == 404

    def test_dashboard_returns_correct_stats(
        self, client, project_with_data, auth_headers
    ):
        """Stats in the dashboard response must reflect actual data counts."""
        resp = client.get(
            f'/api/projects/{project_with_data.id}/dashboard',
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['stats']['total_tasks'] == 1
        assert data['stats']['total_documents'] == 1

    def test_authorization_bypass_via_sequential_ids(
        self, client, db_session, sample_user, other_auth_headers
    ):
        """
        Simulates an attacker enumerating project IDs sequentially.
        Each private project created by sample_user must return 403 for the
        unrelated user, not 200, regardless of the numeric project_id value.
        """
        projects = []
        for i in range(3):
            p = Project(
                name=f'Secret Project {i}',
                description='private',
                owner_id=sample_user.id,
                is_public=False,
            )
            db_session.add(p)
        db_session.commit()

        all_projects = Project.query.filter_by(owner_id=sample_user.id).all()
        for p in all_projects:
            resp = client.get(
                f'/api/projects/{p.id}/dashboard',
                headers=other_auth_headers,
            )
            assert resp.status_code == 403, (
                f"Expected 403 for private project {p.id}, got {resp.status_code}"
            )
