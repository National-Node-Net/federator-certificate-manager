/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service.pki;

import java.util.List;
import java.util.Map;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.VaultException;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.CreateKeyResponseDTO;

/**
 * Interface for providing secrets management capabilities with HashiCorp Vault.
 * Specifically handles persisting key pairs to configured secret paths.
 */
public interface VaultSecretProvider {

    /**
     * Persists a key pair to the configured Vault secret path.
     *
     * @param keyPairDto the DTO containing the public and private keys in PEM format
     * @throws VaultException if persistence fails
     */
    void persistKeyPair(CreateKeyResponseDTO keyPairDto);

    /**
     * Persists a certificate to the configured Vault secret path.
     *
     * @param certificate the certificate in PEM format
     * @throws VaultException if persistence fails
     */
    void persistCertificate(String certificate);

    /**
     * Persists a CA chain to the configured Vault secret path.
     *
     * @param caChain the list of certificates in the chain in PEM format
     * @throws VaultException if persistence fails
     */
    void persistCaChain(List<String> caChain);

    /**
     * Persists the Intermediate CA certificate to the configured Vault secret path.
     *
     * @param intermediateCa the Intermediate CA certificate in PEM format
     * @throws VaultException if persistence fails
     */
    void persistIntermediateCa(String intermediateCa);

    /**
     * Retrieves the certificate from the configured Vault secret path.
     *
     * @return the certificate in PEM format, or null if not found
     * @throws VaultException if retrieval fails
     */
    String getCertificate();

    /**
     * Retrieves the key pair from the configured Vault secret path.
     *
     * @return the DTO containing the public and private keys in PEM format, or null if not found
     * @throws VaultException if retrieval fails
     */
    CreateKeyResponseDTO getKeyPair();

    /**
     * Retrieves the CA chain from the configured Vault secret path.
     *
     * @return the list of certificates in the chain in PEM format, or null if not found
     * @throws VaultException if retrieval fails
     */
    List<String> getCaChain();

    /**
     * Retrieves the Intermediate CA certificate from the configured Vault secret path.
     *
     * @return the Intermediate CA certificate in PEM format, or null if not found
     * @throws VaultException if retrieval fails
     */
    String getIntermediateCa();

    /**
     * Persists a generic secret to the configured Vault secret path.
     *
     * @param suffix the suffix to append to the base path
     * @param secret the secret data as a map
     * @throws VaultException if persistence fails
     */
    void persistSecret(String suffix, Map<String, String> secret);

    /**
     * Retrieves a generic secret from the configured Vault secret path.
     *
     * @param suffix the suffix to append to the base path
     * @return the secret data as a map, or an empty map if not found
     * @throws VaultException if retrieval fails
     */
    Map<String, Object> getSecret(String suffix);
}
