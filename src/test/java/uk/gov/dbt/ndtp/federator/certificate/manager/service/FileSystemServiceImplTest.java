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
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.FileSystemException;

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

    @Test
    void atomicWrite_whenTargetIsNonEmptyDirectory_failsAndRemovesTempFile() throws IOException {
        Path target = Files.createDirectory(tempDir.resolve("store.p12"));
        Files.writeString(target.resolve("occupied"), "x");

        FileSystemException e =
                assertThrows(FileSystemException.class, () -> fileSystemService.atomicWrite(target, new byte[] {1}));

        assertTrue(e.getMessage().startsWith("Failed to atomically write to"));
        try (Stream<Path> files = Files.list(tempDir)) {
            assertTrue(files.noneMatch(f -> f.getFileName().toString().endsWith(".tmp")));
        }
    }

    @Test
    void atomicWrite_whenParentCannotBeCreated_throws() throws IOException {
        Path regularFile = Files.writeString(tempDir.resolve("not-a-directory"), "x");
        Path target = regularFile.resolve("sub").resolve("store.p12");

        FileSystemException e =
                assertThrows(FileSystemException.class, () -> fileSystemService.atomicWrite(target, new byte[] {1}));

        assertTrue(e.getMessage().startsWith("Failed to create directory"));
    }

    @Test
    void atomicWrite_whenParentIsAFile_failsToCreateTempFile() throws IOException {
        Path regularFile = Files.writeString(tempDir.resolve("not-a-directory"), "x");
        Path target = regularFile.resolve("store.p12");

        FileSystemException e =
                assertThrows(FileSystemException.class, () -> fileSystemService.atomicWrite(target, new byte[] {1}));

        assertTrue(e.getMessage().startsWith("Failed to create temporary file"));
    }

    @Test
    void needsUpdate_returnsTrueWhenExistingPathCannotBeRead() throws IOException {
        Path directory = Files.createDirectory(tempDir.resolve("store.p12"));

        assertTrue(fileSystemService.needsUpdate(directory, new byte[] {1}));
    }

    @Test
    void write_whenTargetIsDirectory_throws() throws IOException {
        Path directory = Files.createDirectory(tempDir.resolve("store.password"));

        FileSystemException e =
                assertThrows(FileSystemException.class, () -> fileSystemService.write(directory, new byte[] {1}));

        assertTrue(e.getMessage().startsWith("Failed to write to"));
    }
}
