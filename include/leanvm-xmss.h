#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define PUBLIC_KEY_SIZE 32

#define SIGNATURE_SIZE 1208

typedef enum PQSigningError {
  Success = 0,
  EncodingAttemptsExceeded = 1,
  InvalidPointer = 2,
  InvalidMessageLength = 3,
  InvalidEpoch = 4,
  UnknownError = 99,
} PQSigningError;

typedef struct PQSignatureSchemeSecretKey {
  uint8_t _private[0];
} PQSignatureSchemeSecretKey;

typedef struct PQSignatureSchemePublicKey {
  uint8_t _private[0];
} PQSignatureSchemePublicKey;

typedef struct PQSignature {
  uint8_t _private[0];
} PQSignature;

typedef struct PQRange {
  uint64_t start;
  uint64_t end;
} PQRange;

typedef struct PQAggregatedSignatureChild {
  const struct PQSignatureSchemePublicKey *const *pubkeys;
  uintptr_t pubkey_count;
  const uint8_t *agg_bytes;
  uintptr_t agg_len;
} PQAggregatedSignatureChild;

typedef struct PQRawXmssSignature {
  const struct PQSignatureSchemePublicKey *pubkey;
  const struct PQSignature *signature;
} PQRawXmssSignature;

typedef struct PQTypeTwoComponent {
  const struct PQSignatureSchemePublicKey *const *pubkeys;
  uintptr_t pubkey_count;
} PQTypeTwoComponent;

typedef struct PQTypeTwoMessageBinding {
  const uint8_t *message;
  uintptr_t message_len;
  uint64_t epoch;
} PQTypeTwoMessageBinding;

void pq_secret_key_free(struct PQSignatureSchemeSecretKey *key);

void pq_public_key_free(struct PQSignatureSchemePublicKey *key);

void pq_signature_free(struct PQSignature *signature);

void pq_string_free(char *s);

char *pq_take_last_error_message(void);

struct PQRange pq_get_activation_interval(const struct PQSignatureSchemeSecretKey *key);

struct PQRange pq_get_prepared_interval(const struct PQSignatureSchemeSecretKey *key);

void pq_advance_preparation(struct PQSignatureSchemeSecretKey *key);

uint64_t pq_get_lifetime(void);

uintptr_t pq_get_signature_size(void);

uintptr_t pq_get_public_key_size(void);

enum PQSigningError pq_key_gen(uintptr_t activation_epoch,
                               uintptr_t num_active_epochs,
                               struct PQSignatureSchemePublicKey **pk_out,
                               struct PQSignatureSchemeSecretKey **sk_out);

enum PQSigningError pq_sign(const struct PQSignatureSchemeSecretKey *sk,
                            uint64_t epoch,
                            const uint8_t *message,
                            uintptr_t message_len,
                            struct PQSignature **signature_out);

int pq_verify(const struct PQSignatureSchemePublicKey *pk,
              uint64_t epoch,
              const uint8_t *message,
              uintptr_t message_len,
              const struct PQSignature *signature);

int pq_verify_ssz(const uint8_t *pubkey_bytes,
                  uintptr_t pubkey_len,
                  uint64_t epoch,
                  const uint8_t *message,
                  uintptr_t message_len,
                  const uint8_t *signature_bytes,
                  uintptr_t signature_len);

char *pq_error_description(enum PQSigningError error);

enum PQSigningError pq_secret_key_serialize(const struct PQSignatureSchemeSecretKey *sk,
                                            uint8_t *buffer,
                                            uintptr_t buffer_len,
                                            uintptr_t *written_len);

enum PQSigningError pq_secret_key_deserialize(const uint8_t *buffer,
                                              uintptr_t buffer_len,
                                              struct PQSignatureSchemeSecretKey **sk_out);

enum PQSigningError pq_secret_key_from_json(const uint8_t *json,
                                            uintptr_t json_len,
                                            struct PQSignatureSchemeSecretKey **sk_out);

enum PQSigningError pq_public_key_serialize(const struct PQSignatureSchemePublicKey *pk,
                                            uint8_t *buffer,
                                            uintptr_t buffer_len,
                                            uintptr_t *written_len);

enum PQSigningError pq_public_key_deserialize(const uint8_t *buffer,
                                              uintptr_t buffer_len,
                                              struct PQSignatureSchemePublicKey **pk_out);

enum PQSigningError pq_public_key_from_json(const uint8_t *json,
                                            uintptr_t json_len,
                                            struct PQSignatureSchemePublicKey **pk_out);

enum PQSigningError pq_signature_serialize(const struct PQSignature *signature,
                                           uint8_t *buffer,
                                           uintptr_t buffer_len,
                                           uintptr_t *written_len);

enum PQSigningError pq_signature_deserialize(const uint8_t *buffer,
                                             uintptr_t buffer_len,
                                             struct PQSignature **signature_out);

enum PQSigningError pq_signature_from_json(const uint8_t *json,
                                           uintptr_t json_len,
                                           struct PQSignature **signature_out);

void pq_xmss_aggregation_setup_prover(void);

void pq_xmss_aggregation_setup_prover_without_arena(void);

void pq_xmss_aggregation_setup_verifier(void);

enum PQSigningError pq_aggregate_signatures(const struct PQSignatureSchemePublicKey *const *pubkeys,
                                            const struct PQSignature *const *signatures,
                                            uintptr_t count,
                                            const uint8_t *message,
                                            uintptr_t message_len,
                                            uint64_t epoch,
                                            uintptr_t log_inv_rate,
                                            uint8_t *buffer,
                                            uintptr_t buffer_len,
                                            uintptr_t *written_len);

enum PQSigningError pq_aggregate_signatures_unverified(const struct PQSignatureSchemePublicKey *const *pubkeys,
                                                       const struct PQSignature *const *signatures,
                                                       uintptr_t count,
                                                       const uint8_t *message,
                                                       uintptr_t message_len,
                                                       uint64_t epoch,
                                                       uintptr_t log_inv_rate,
                                                       uint8_t *buffer,
                                                       uintptr_t buffer_len,
                                                       uintptr_t *written_len);

enum PQSigningError pq_aggregate_signatures_recursive(const struct PQAggregatedSignatureChild *children,
                                                      uintptr_t child_count,
                                                      const struct PQRawXmssSignature *raw_xmss,
                                                      uintptr_t raw_xmss_count,
                                                      const uint8_t *message,
                                                      uintptr_t message_len,
                                                      uint64_t epoch,
                                                      uintptr_t log_inv_rate,
                                                      uint8_t *buffer,
                                                      uintptr_t buffer_len,
                                                      uintptr_t *written_len);

enum PQSigningError pq_aggregate_signatures_recursive_unverified(const struct PQAggregatedSignatureChild *children,
                                                                 uintptr_t child_count,
                                                                 const struct PQRawXmssSignature *raw_xmss,
                                                                 uintptr_t raw_xmss_count,
                                                                 const uint8_t *message,
                                                                 uintptr_t message_len,
                                                                 uint64_t epoch,
                                                                 uintptr_t log_inv_rate,
                                                                 uint8_t *buffer,
                                                                 uintptr_t buffer_len,
                                                                 uintptr_t *written_len);

int pq_verify_aggregated_signatures(const struct PQSignatureSchemePublicKey *const *pubkeys,
                                    uintptr_t count,
                                    const uint8_t *message,
                                    uintptr_t message_len,
                                    const uint8_t *agg_bytes,
                                    uintptr_t agg_len,
                                    uint64_t epoch);

enum PQSigningError pq_merge_many_type_1(const struct PQAggregatedSignatureChild *entries,
                                         uintptr_t entry_count,
                                         uintptr_t log_inv_rate,
                                         uint8_t *buffer,
                                         uintptr_t buffer_len,
                                         uintptr_t *written_len);

int pq_verify_type_2_with_messages(const struct PQTypeTwoComponent *components,
                                   uintptr_t component_count,
                                   const struct PQTypeTwoMessageBinding *bindings,
                                   uintptr_t binding_count,
                                   const uint8_t *type2_bytes,
                                   uintptr_t type2_len);

enum PQSigningError pq_split_type_2_by_message(const struct PQTypeTwoComponent *components,
                                               uintptr_t component_count,
                                               const uint8_t *type2_bytes,
                                               uintptr_t type2_len,
                                               const uint8_t *message,
                                               uintptr_t message_len,
                                               uintptr_t log_inv_rate,
                                               uint8_t *buffer,
                                               uintptr_t buffer_len,
                                               uintptr_t *written_len);
