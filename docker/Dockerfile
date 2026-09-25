
#
# SPDX-License-Identifier: Apache-2.0
# © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
# attributed to the Department for Business and Trade (UK) as the governing entity.
#

# Build stage
ARG JAR_FILE=federator-certificate-manager-1.0.0.jar
FROM maven:3.9.6-eclipse-temurin-21-alpine AS build
ARG JAR_FILE
WORKDIR /build

# Copy the project files
COPY pom.xml .
COPY src ./src

# Build the application
RUN mvn -B clean package -DskipTests

# Runtime stage
# Name this stage so CI can target it (matches --target federator-certificate-manager in workflows)
FROM eclipse-temurin:21-jdk-alpine AS federator-certificate-manager

# Patch OS-level packages to pick up latest security fixes (Trivy)
RUN apk update && apk upgrade --no-cache

# Create non-root user and group
RUN addgroup -S app && adduser -S -G app -u 10001 app

WORKDIR /app

# Create directories and set permissions
RUN mkdir -p /app/docker /app/logs /app/tmp && chown -R app:app /app

# Copy application jar from build stage
# Use the jar name provided by CI via --build-arg JAR_NAME="federator-certificate-manager-${version}"
ARG JAR_NAME
COPY --from=build /build/target/${JAR_NAME}.jar /app/app.jar

RUN chown app:app /app/app.jar

# Use non-root user from here on
USER app:app

# Helpful defaults for Java in containers
ENV JAVA_OPTS="-Djava.security.egd=file:/dev/./urandom -XX:MaxRAMPercentage=75.0 -Djava.io.tmpdir=/app/tmp"

# Use sh -c so JAVA_OPTS is expanded
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar /app/app.jar"]