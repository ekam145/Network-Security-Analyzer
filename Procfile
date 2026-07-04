web: cd backend && gunicorn app:app
worker: cd frontend && streamlit run dashboard.py --server.port $PORT --server.address 0.0.0.0
