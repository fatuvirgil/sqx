#!/bin/bash
# MSSQL entrypoint wrapper to execute init scripts

# Start SQL Server in background
/opt/mssql/bin/sqlservr &

# Wait for SQL Server to be ready
echo "Waiting for SQL Server to start..."
sleep 30

# Check if SQL Server is ready
for i in {1..30}; do
    if /opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P "${SA_PASSWORD}" -Q "SELECT 1" &>/dev/null; then
        echo "SQL Server is ready"
        break
    fi
    echo "Waiting for SQL Server... attempt $i"
    sleep 5
done

# Create database
echo "Creating security database..."
/opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P "${SA_PASSWORD}" -Q "CREATE DATABASE security"

# Execute init scripts
for f in /docker-entrypoint-initdb.d/*.sql; do
    if [ -f "$f" ]; then
        echo "Executing $f..."
        /opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P "${SA_PASSWORD}" -d security -i "$f"
    fi
done

echo "MSSQL initialization complete"

# Keep SQL Server running
wait
