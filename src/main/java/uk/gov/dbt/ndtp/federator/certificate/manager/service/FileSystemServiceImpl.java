/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.FileSystemException;

/**
 * Implementation of FileSystemService for standard file operations.
 */
@Slf4j
@Service
public class FileSystemServiceImpl implements FileSystemService {

    @Override
    public void atomicWrite(Path targetPath, byte[] content) {
        Path parentDir = targetPath.getParent();
        ensureDirectoryExists(parentDir);

        Path tempFile = createTempFile(parentDir, targetPath);
        try {
            Files.write(tempFile, content);
            Files.move(tempFile, targetPath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (Exception e) {
            deleteTempFileQuietly(tempFile);
            throw new FileSystemException("Failed to atomically write to " + targetPath, e);
        }
    }

    private void ensureDirectoryExists(Path directory) {
        try {
            if (directory != null && !Files.exists(directory)) {
                Files.createDirectories(directory);
            }
        } catch (Exception e) {
            throw new FileSystemException("Failed to create directory: " + directory, e);
        }
    }

    private Path createTempFile(Path parentDir, Path targetPath) {
        try {
            return Files.createTempFile(parentDir, targetPath.getFileName().toString(), ".tmp");
        } catch (Exception e) {
            throw new FileSystemException("Failed to create temporary file in " + parentDir, e);
        }
    }

    private void deleteTempFileQuietly(Path tempFile) {
        try {
            Files.deleteIfExists(tempFile);
        } catch (Exception e) {
            log.warn("Failed to delete temporary file {}: {}", tempFile, e.getMessage());
        }
    }

    @Override
    public boolean needsUpdate(Path path, byte[] content) {
        if (!Files.exists(path)) {
            return true;
        }
        try {
            byte[] existingContent = Files.readAllBytes(path);
            return !Arrays.equals(existingContent, content);
        } catch (Exception e) {
            log.warn(
                    "Failed to read existing file {} for comparison: {}. Assuming update is needed.",
                    path,
                    e.getMessage());
            return true;
        }
    }

    @Override
    public void write(Path path, byte[] content) {
        Path parentDir = path.getParent();
        ensureDirectoryExists(parentDir);
        try {
            Files.write(path, content);
        } catch (Exception e) {
            throw new FileSystemException("Failed to write to " + path, e);
        }
    }
}
