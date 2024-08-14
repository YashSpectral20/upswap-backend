# Use the official PostgreSQL image from the Docker Hub
FROM postgres:13

# Set environment variables
ENV POSTGRES_DB=mydatabase
ENV POSTGRES_USER=myuser
ENV POSTGRES_PASSWORD=mypassword

# Expose the default PostgreSQL port
EXPOSE 5432

# Copy any custom configuration or SQL scripts if needed
# COPY ./init.sql /docker-entrypoint-initdb.d/

# No need to specify CMD or ENTRYPOINT, as the base image already does that
