/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service;

import java.nio.file.Path;

/**
 * Service for low-level file system operations.
 */
public interface FileSystemService {
    /**
     * Atomically writes content to a file.
     *
     * @param targetPath the target file path
     * @param content    the content to write
     * @throws uk.gov.dbt.ndtp.federator.certificate.manager.exception.FileSystemException if writing fails
     */
    void atomicWrite(Path targetPath, byte[] content);

    /**
     * Checks if a file's content matches the provided content.
     *
     * @param path    the file path to check
     * @param content the content to compare against
     * @return true if the file needs updating (missing or content differs), false otherwise
     */
    boolean needsUpdate(Path path, byte[] content);

    /**
     * Writes content to a file.
     *
     * @param path    the target file path
     * @param content the content to write
     * @throws uk.gov.dbt.ndtp.federator.certificate.manager.exception.FileSystemException if writing fails
     */
    void write(Path path, byte[] content);
}
