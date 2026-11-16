/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FileSystemServiceImplTest {

    @TempDir
    Path tempDir;

    private FileSystemServiceImpl fileSystemService;

    @BeforeEach
    void setUp() {
        fileSystemService = new FileSystemServiceImpl();
    }

    @Test
    void atomicWrite_writesFileSuccessfully() throws IOException {
        Path target = tempDir.resolve("test.bin");
        byte[] content = "hello world".getBytes();

        fileSystemService.atomicWrite(target, content);

        assertTrue(Files.exists(target));
        assertArrayEquals(content, Files.readAllBytes(target));
    }

    @Test
    void atomicWrite_createsParentDirectories() throws IOException {
        Path target = tempDir.resolve("sub/dir/test.bin");
        byte[] content = "nested content".getBytes();

        fileSystemService.atomicWrite(target, content);

        assertTrue(Files.exists(target));
        assertArrayEquals(content, Files.readAllBytes(target));
    }

    @Test
    void needsUpdate_returnsTrueWhenFileDoesNotExist() {
        Path nonExistent = tempDir.resolve("missing.bin");
        assertTrue(fileSystemService.needsUpdate(nonExistent, "data".getBytes()));
    }

    @Test
    void needsUpdate_returnsFalseWhenContentMatches() throws IOException {
        Path file = tempDir.resolve("existing.bin");
        byte[] content = "same content".getBytes();
        Files.write(file, content);

        assertFalse(fileSystemService.needsUpdate(file, content));
    }

    @Test
    void needsUpdate_returnsTrueWhenContentDiffers() throws IOException {
        Path file = tempDir.resolve("existing.bin");
        Files.write(file, "old content".getBytes());

        assertTrue(fileSystemService.needsUpdate(file, "new content".getBytes()));
    }

    @Test
    void write_writesFileSuccessfully() throws IOException {
        Path target = tempDir.resolve("write-test.bin");
        byte[] content = "write test".getBytes();

        fileSystemService.write(target, content);

        assertTrue(Files.exists(target));
        assertArrayEquals(content, Files.readAllBytes(target));
    }
}
