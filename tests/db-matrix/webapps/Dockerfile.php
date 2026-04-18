FROM php:7.4-apache

# Install PDO MySQL, PostgreSQL, SQLite, and Firebird
RUN apt-get update && apt-get install -y \
    libpq-dev \
    libsqlite3-dev \
    libfbclient2 \
    libib-util \
    firebird-dev \
    unzip \
    libzip-dev \
    curl \
    libcurl4-openssl-dev \
    && docker-php-ext-install pdo pdo_mysql pdo_pgsql pdo_sqlite mysqli curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Firebird PDO driver (if available) or use ODBC
RUN apt-get update && apt-get install -y \
    odbc-postgresql \
    libodbc1 \
    odbcinst \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Enable Apache mod_rewrite
RUN a2enmod rewrite

# Set working directory
WORKDIR /var/www/html
