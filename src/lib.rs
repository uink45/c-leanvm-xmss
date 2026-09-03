#[cfg(not(feature = "jemalloc"))]
use std::alloc::System;
use std::alloc::{GlobalAlloc, Layout};
use std::cell::RefCell;
use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use lean_multisig::{
    aggregate_single_message_signatures as aggregate_type_1,
    merge_single_message_aggregates as merge_many_type_1, setup_prover, setup_prover_without_arena,
    setup_verifier, split_multi_message_aggregate, verify_multi_message_aggregate as verify_type_2,
    verify_single_message_aggregate as verify_type_1, xmss_key_gen, xmss_sign, xmss_verify,
    MultiMessageAggregateSignature as TypeTwoMultiSignature,
    SingleMessageAggregateSignature as TypeOneMultiSignature, XmssPublicKey, XmssSecretKey,
    XmssSignature, XmssSignatureError, MESSAGE_LEN_BYTES as MESSAGE_LENGTH,
};
use ssz::{Decode, Encode};

static WIPING_DEALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static WIPED_ALLOCATION_COUNT: AtomicUsize = AtomicUsize::new(0);

struct WipingAllocator<A>(A);

unsafe impl<A: GlobalAlloc> GlobalAlloc for WipingAllocator<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { self.0.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { self.0.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, allocation: *mut u8, layout: Layout) {
        if WIPING_DEALLOCATIONS.load(Ordering::Relaxed) > 0 {
            unsafe { secure_zero_allocation(allocation, layout.size()) };
            #[cfg(test)]
            WIPED_ALLOCATION_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { self.0.dealloc(allocation, layout) };
    }

    unsafe fn realloc(&self, allocation: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if WIPING_DEALLOCATIONS.load(Ordering::Relaxed) == 0 {
            return unsafe { self.0.realloc(allocation, layout, new_size) };
        }

        let Ok(new_layout) = Layout::from_size_align(new_size, layout.align()) else {
            return ptr::null_mut();
        };
        let new_allocation = unsafe { self.0.alloc(new_layout) };
        if new_allocation.is_null() {
            return ptr::null_mut();
        }
        unsafe {
            ptr::copy_nonoverlapping(allocation, new_allocation, layout.size().min(new_size));
            secure_zero_allocation(allocation, layout.size());
            self.0.dealloc(allocation, layout);
        }
        new_allocation
    }
}

#[cfg(feature = "jemalloc")]
#[global_allocator]
static ALLOC: WipingAllocator<tikv_jemallocator::Jemalloc> =
    WipingAllocator(tikv_jemallocator::Jemalloc);

#[cfg(not(feature = "jemalloc"))]
#[global_allocator]
static ALLOC: WipingAllocator<System> = WipingAllocator(System);

unsafe fn secure_zero_allocation(allocation: *mut u8, size: usize) {
    for offset in 0..size {
        unsafe { allocation.add(offset).write_volatile(0) };
    }
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
}

struct WipeDeallocationGuard;

impl WipeDeallocationGuard {
    fn new() -> Self {
        // The secret type has private nested allocations. Wipe each allocation
        // while its owner runs the normal Rust destructor.
        WIPING_DEALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        Self
    }
}

impl Drop for WipeDeallocationGuard {
    fn drop(&mut self) {
        WIPING_DEALLOCATIONS.fetch_sub(1, Ordering::Relaxed);
    }
}

pub const PUBLIC_KEY_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 1208;
const _: () = assert!(PUBLIC_KEY_SIZE == lean_multisig::PUB_KEY_SSZ_LEN);
const _: () = assert!(SIGNATURE_SIZE == lean_multisig::SIGNATURE_SSZ_LEN);

#[cfg(test)]
const DEFAULT_LOG_INV_RATE: usize = 2;

type PublicKeyType = XmssPublicKey;
type SecretKeyType = XmssSecretKey;
type SignatureType = XmssSignature;

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = RefCell::new(None);
}

static PROVING_PHASE_LOCK: Mutex<()> = Mutex::new(());

#[repr(C)]
pub struct PQSignatureSchemeSecretKey {
    _private: [u8; 0],
}

#[repr(C)]
pub struct PQSignatureSchemePublicKey {
    _private: [u8; 0],
}

#[repr(C)]
pub struct PQSignature {
    _private: [u8; 0],
}

#[repr(C)]
pub struct PQRawXmssSignature {
    pub pubkey: *const PQSignatureSchemePublicKey,
    pub signature: *const PQSignature,
}

#[repr(C)]
pub struct PQAggregatedSignatureChild {
    pub pubkeys: *const *const PQSignatureSchemePublicKey,
    pub pubkey_count: usize,
    pub agg_bytes: *const u8,
    pub agg_len: usize,
}

#[repr(C)]
pub struct PQTypeTwoComponent {
    pub pubkeys: *const *const PQSignatureSchemePublicKey,
    pub pubkey_count: usize,
}

#[repr(C)]
pub struct PQTypeTwoMessageBinding {
    pub message: *const u8,
    pub message_len: usize,
    pub epoch: u64,
}

struct PQSignatureSchemeSecretKeyInner {
    inner: Box<SecretKeyType>,
}

struct PQSignatureSchemePublicKeyInner {
    inner: Box<PublicKeyType>,
}

struct PQSignatureInner {
    inner: Box<SignatureType>,
}

#[repr(C)]
pub struct PQRange {
    pub start: u64,
    pub end: u64,
}

impl From<std::ops::RangeInclusive<u32>> for PQRange {
    fn from(range: std::ops::RangeInclusive<u32>) -> Self {
        Self {
            start: u64::from(*range.start()),
            end: u64::from(*range.end()) + 1,
        }
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
pub enum PQSigningError {
    Success = 0,
    EncodingAttemptsExceeded = 1,
    InvalidPointer = 2,
    InvalidMessageLength = 3,
    InvalidEpoch = 4,
    UnknownError = 99,
}

fn epoch_to_u32(epoch: u64) -> Result<u32, PQSigningError> {
    u32::try_from(epoch).map_err(|_| PQSigningError::InvalidEpoch)
}

unsafe fn message_from_ptr(
    message: *const u8,
    message_len: usize,
) -> Result<[u8; MESSAGE_LENGTH], PQSigningError> {
    if message.is_null() {
        return Err(PQSigningError::InvalidPointer);
    }
    if message_len != MESSAGE_LENGTH {
        return Err(PQSigningError::InvalidMessageLength);
    }

    let message_slice = slice::from_raw_parts(message, message_len);
    let mut message_array = [0u8; MESSAGE_LENGTH];
    message_array.copy_from_slice(message_slice);
    Ok(message_array)
}

fn normalize_signature_bytes(bytes: &[u8]) -> Result<&[u8], PQSigningError> {
    if bytes.len() == SIGNATURE_SIZE {
        return Ok(bytes);
    }

    if bytes.len() > SIGNATURE_SIZE {
        let (signature_bytes, trailing_padding) = bytes.split_at(SIGNATURE_SIZE);
        if trailing_padding.iter().all(|byte| *byte == 0) {
            return Ok(signature_bytes);
        }
    }

    Err(PQSigningError::UnknownError)
}

fn set_last_error(message: impl Into<String>) {
    LAST_ERROR.with(|last_error| {
        *last_error.borrow_mut() = Some(message.into());
    });
}

fn clear_last_error() {
    LAST_ERROR.with(|last_error| {
        *last_error.borrow_mut() = None;
    });
}

fn cstring_from_message(message: String) -> CString {
    let bytes = message
        .into_bytes()
        .into_iter()
        .map(|byte| if byte == 0 { b' ' } else { byte })
        .collect::<Vec<_>>();
    CString::new(bytes)
        .unwrap_or_else(|_| CString::new("leanvm-xmss: error detail unavailable").unwrap())
}

fn aggregation_error(stage: &str, err: impl std::fmt::Display) -> PQSigningError {
    set_last_error(format!("leanvm-xmss: {stage} failed: {err}"));
    PQSigningError::UnknownError
}

fn run_proving_phase_then<T, E, R>(
    f: impl FnOnce() -> Result<T, E>,
    after: impl FnOnce(T) -> R,
) -> Result<Result<R, E>, ()> {
    let _guard = PROVING_PHASE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    catch_unwind(AssertUnwindSafe(|| f().map(after))).map_err(|_| ())
}

unsafe fn write_bytes_to_buffer(
    bytes: &[u8],
    buffer: *mut u8,
    buffer_len: usize,
    written_len: *mut usize,
) -> PQSigningError {
    if buffer.is_null() || written_len.is_null() {
        return PQSigningError::InvalidPointer;
    }

    if bytes.len() > buffer_len {
        *written_len = bytes.len();
        return PQSigningError::UnknownError;
    }

    let buffer_slice = slice::from_raw_parts_mut(buffer, buffer_len);
    buffer_slice[..bytes.len()].copy_from_slice(bytes);
    *written_len = bytes.len();
    PQSigningError::Success
}

fn collect_public_keys(
    keys: *const *const PQSignatureSchemePublicKey,
    count: usize,
) -> Result<Vec<PublicKeyType>, PQSigningError> {
    if count == 0 {
        return Ok(Vec::new());
    }
    if keys.is_null() {
        return Err(PQSigningError::InvalidPointer);
    }

    let key_ptrs = unsafe { slice::from_raw_parts(keys, count) };
    let mut out = Vec::with_capacity(count);

    for key_ptr in key_ptrs {
        if key_ptr.is_null() {
            return Err(PQSigningError::InvalidPointer);
        }

        let key = unsafe { &*(*key_ptr as *const PQSignatureSchemePublicKeyInner) };
        out.push((*key.inner).clone());
    }

    Ok(out)
}

fn collect_signatures(
    signatures: *const *const PQSignature,
    count: usize,
) -> Result<Vec<SignatureType>, PQSigningError> {
    if count == 0 {
        return Ok(Vec::new());
    }
    if signatures.is_null() {
        return Err(PQSigningError::InvalidPointer);
    }

    let sig_ptrs = unsafe { slice::from_raw_parts(signatures, count) };
    let mut out = Vec::with_capacity(count);

    for sig_ptr in sig_ptrs {
        if sig_ptr.is_null() {
            return Err(PQSigningError::InvalidPointer);
        }

        let sig = unsafe { &*(*sig_ptr as *const PQSignatureInner) };
        out.push((*sig.inner).clone());
    }

    Ok(out)
}

fn collect_raw_xmss_inputs(
    raw_xmss: *const PQRawXmssSignature,
    raw_xmss_count: usize,
    message: &[u8; MESSAGE_LENGTH],
    epoch: u32,
    verify_inputs: bool,
) -> Result<Vec<(PublicKeyType, SignatureType)>, PQSigningError> {
    if raw_xmss_count == 0 {
        return Ok(Vec::new());
    }
    if raw_xmss.is_null() {
        return Err(PQSigningError::InvalidPointer);
    }

    let raw_inputs = unsafe { slice::from_raw_parts(raw_xmss, raw_xmss_count) };
    let mut out = Vec::with_capacity(raw_xmss_count);

    for raw_input in raw_inputs {
        if raw_input.pubkey.is_null() || raw_input.signature.is_null() {
            return Err(PQSigningError::InvalidPointer);
        }

        let public_key = unsafe { &*(raw_input.pubkey as *const PQSignatureSchemePublicKeyInner) };
        let signature = unsafe { &*(raw_input.signature as *const PQSignatureInner) };
        let public_key = (*public_key.inner).clone();
        let signature = (*signature.inner).clone();

        if verify_inputs && xmss_verify(&public_key, epoch, message, &signature).is_err() {
            return Err(PQSigningError::UnknownError);
        }

        out.push((public_key, signature));
    }

    Ok(out)
}

fn collect_child_aggregations(
    children: *const PQAggregatedSignatureChild,
    child_count: usize,
) -> Result<Vec<TypeOneMultiSignature>, PQSigningError> {
    if child_count == 0 {
        return Ok(Vec::new());
    }
    if children.is_null() {
        return Err(PQSigningError::InvalidPointer);
    }

    let child_inputs = unsafe { slice::from_raw_parts(children, child_count) };
    let mut out = Vec::with_capacity(child_count);

    for child in child_inputs {
        if child.agg_bytes.is_null() {
            return Err(PQSigningError::InvalidPointer);
        }

        let pubkeys = collect_public_keys(child.pubkeys, child.pubkey_count)?;
        let proof_bytes = unsafe { slice::from_raw_parts(child.agg_bytes, child.agg_len) };
        let aggregated = TypeOneMultiSignature::from_bytes_without_pubkeys(proof_bytes, pubkeys)
            .ok_or(PQSigningError::UnknownError)?;
        out.push(aggregated);
    }

    Ok(out)
}

fn collect_type2_components(
    components: *const PQTypeTwoComponent,
    component_count: usize,
) -> Result<Vec<Vec<PublicKeyType>>, PQSigningError> {
    if component_count == 0 {
        return Ok(Vec::new());
    }
    if components.is_null() {
        return Err(PQSigningError::InvalidPointer);
    }

    let inputs = unsafe { slice::from_raw_parts(components, component_count) };
    let mut out = Vec::with_capacity(component_count);
    for component in inputs {
        out.push(collect_public_keys(
            component.pubkeys,
            component.pubkey_count,
        )?);
    }
    Ok(out)
}

unsafe fn collect_type2_message_bindings(
    bindings: *const PQTypeTwoMessageBinding,
    binding_count: usize,
) -> Result<Vec<([u8; MESSAGE_LENGTH], u32)>, PQSigningError> {
    if binding_count == 0 {
        return Ok(Vec::new());
    }
    if bindings.is_null() {
        return Err(PQSigningError::InvalidPointer);
    }

    let inputs = slice::from_raw_parts(bindings, binding_count);
    let mut out = Vec::with_capacity(binding_count);
    for binding in inputs {
        let epoch = epoch_to_u32(binding.epoch)?;
        let message = message_from_ptr(binding.message, binding.message_len)?;
        out.push((message, epoch));
    }
    Ok(out)
}

fn collect_type1_entries(
    entries: *const PQAggregatedSignatureChild,
    entry_count: usize,
) -> Result<Vec<TypeOneMultiSignature>, PQSigningError> {
    if entry_count == 0 {
        return Ok(Vec::new());
    }
    if entries.is_null() {
        return Err(PQSigningError::InvalidPointer);
    }

    let inputs = unsafe { slice::from_raw_parts(entries, entry_count) };
    let mut out = Vec::with_capacity(entry_count);
    for entry in inputs {
        if entry.agg_bytes.is_null() {
            return Err(PQSigningError::InvalidPointer);
        }
        let pubkeys = collect_public_keys(entry.pubkeys, entry.pubkey_count)?;
        let sig_bytes = unsafe { slice::from_raw_parts(entry.agg_bytes, entry.agg_len) };
        let type1 = TypeOneMultiSignature::from_bytes_without_pubkeys(sig_bytes, pubkeys)
            .ok_or(PQSigningError::UnknownError)?;
        out.push(type1);
    }
    Ok(out)
}

unsafe fn aggregate_signatures_impl(
    children: *const PQAggregatedSignatureChild,
    child_count: usize,
    raw_xmss: *const PQRawXmssSignature,
    raw_xmss_count: usize,
    message: *const u8,
    message_len: usize,
    epoch: u64,
    log_inv_rate: usize,
    buffer: *mut u8,
    buffer_len: usize,
    written_len: *mut usize,
    verify_inputs: bool,
) -> PQSigningError {
    if buffer.is_null() || written_len.is_null() {
        return PQSigningError::InvalidPointer;
    }
    if (child_count > 0 && children.is_null())
        || (raw_xmss_count > 0 && raw_xmss.is_null())
        || message.is_null()
    {
        return PQSigningError::InvalidPointer;
    }
    if child_count == 0 && raw_xmss_count == 0 {
        return PQSigningError::UnknownError;
    }

    let epoch32 = match epoch_to_u32(epoch) {
        Ok(epoch32) => epoch32,
        Err(err) => return err,
    };
    let message_array = match message_from_ptr(message, message_len) {
        Ok(message_array) => message_array,
        Err(err) => return err,
    };
    let raw_xmss_inputs = match collect_raw_xmss_inputs(
        raw_xmss,
        raw_xmss_count,
        &message_array,
        epoch32,
        verify_inputs,
    ) {
        Ok(raw_xmss_inputs) => raw_xmss_inputs,
        Err(err) => return err,
    };
    let child_inputs = match collect_child_aggregations(children, child_count) {
        Ok(child_inputs) => child_inputs,
        Err(err) => return err,
    };

    let aggregated_bytes = match run_proving_phase_then(
        || {
            aggregate_type_1(
                &child_inputs,
                raw_xmss_inputs,
                message_array,
                epoch32,
                log_inv_rate,
            )
        },
        |aggregated| aggregated.to_bytes_without_pubkeys(),
    ) {
        Ok(Ok(aggregated_bytes)) => aggregated_bytes,
        Ok(Err(err)) => return aggregation_error("aggregate_type_1", err),
        Err(_) => return PQSigningError::UnknownError,
    };

    write_bytes_to_buffer(&aggregated_bytes, buffer, buffer_len, written_len)
}

#[no_mangle]
pub unsafe extern "C" fn pq_secret_key_free(key: *mut PQSignatureSchemeSecretKey) {
    if !key.is_null() {
        let _wipe_guard = WipeDeallocationGuard::new();
        let _ = Box::from_raw(key as *mut PQSignatureSchemeSecretKeyInner);
    }
}

#[no_mangle]
pub unsafe extern "C" fn pq_public_key_free(key: *mut PQSignatureSchemePublicKey) {
    if !key.is_null() {
        let _ = Box::from_raw(key as *mut PQSignatureSchemePublicKeyInner);
    }
}

#[no_mangle]
pub unsafe extern "C" fn pq_signature_free(signature: *mut PQSignature) {
    if !signature.is_null() {
        let _ = Box::from_raw(signature as *mut PQSignatureInner);
    }
}

#[no_mangle]
pub unsafe extern "C" fn pq_string_free(s: *mut c_char) {
    if !s.is_null() {
        let _ = CString::from_raw(s);
    }
}

#[no_mangle]
pub extern "C" fn pq_take_last_error_message() -> *mut c_char {
    LAST_ERROR.with(|last_error| match last_error.borrow_mut().take() {
        Some(message) => cstring_from_message(message).into_raw(),
        None => std::ptr::null_mut(),
    })
}

#[no_mangle]
pub unsafe extern "C" fn pq_get_activation_interval(
    key: *const PQSignatureSchemeSecretKey,
) -> PQRange {
    if key.is_null() {
        return PQRange { start: 0, end: 0 };
    }

    let key = &*(key as *const PQSignatureSchemeSecretKeyInner);
    key.inner.activation_slots().into()
}

#[no_mangle]
pub unsafe extern "C" fn pq_get_prepared_interval(
    key: *const PQSignatureSchemeSecretKey,
) -> PQRange {
    if key.is_null() {
        return PQRange { start: 0, end: 0 };
    }

    let key = &*(key as *const PQSignatureSchemeSecretKeyInner);
    key.inner.activation_slots().into()
}

#[no_mangle]
pub unsafe extern "C" fn pq_advance_preparation(key: *mut PQSignatureSchemeSecretKey) {
    let _ = key;
}

#[no_mangle]
pub extern "C" fn pq_get_lifetime() -> u64 {
    1u64 << 32
}

#[no_mangle]
pub extern "C" fn pq_get_signature_size() -> usize {
    SIGNATURE_SIZE
}

#[no_mangle]
pub extern "C" fn pq_get_public_key_size() -> usize {
    PUBLIC_KEY_SIZE
}

#[no_mangle]
pub unsafe extern "C" fn pq_key_gen(
    activation_epoch: usize,
    num_active_epochs: usize,
    pk_out: *mut *mut PQSignatureSchemePublicKey,
    sk_out: *mut *mut PQSignatureSchemeSecretKey,
) -> PQSigningError {
    if pk_out.is_null() || sk_out.is_null() {
        return PQSigningError::InvalidPointer;
    }

    let activation_epoch = match u64::try_from(activation_epoch) {
        Ok(epoch) => epoch,
        Err(_) => return PQSigningError::InvalidEpoch,
    };
    let num_active_epochs = match u64::try_from(num_active_epochs) {
        Ok(count) => count,
        Err(_) => return PQSigningError::InvalidEpoch,
    };

    let mut rng = rand::rng();
    let (pk, sk) = match catch_unwind(AssertUnwindSafe(|| {
        xmss_key_gen(&mut rng, activation_epoch, num_active_epochs)
    })) {
        Ok(Ok(keys)) => keys,
        Ok(Err(_)) => return PQSigningError::InvalidEpoch,
        Err(_) => return PQSigningError::UnknownError,
    };

    let pk_wrapper = Box::new(PQSignatureSchemePublicKeyInner {
        inner: Box::new(pk),
    });
    let sk_wrapper = Box::new(PQSignatureSchemeSecretKeyInner {
        inner: Box::new(sk),
    });

    *pk_out = Box::into_raw(pk_wrapper) as *mut PQSignatureSchemePublicKey;
    *sk_out = Box::into_raw(sk_wrapper) as *mut PQSignatureSchemeSecretKey;
    PQSigningError::Success
}

#[no_mangle]
pub unsafe extern "C" fn pq_sign(
    sk: *const PQSignatureSchemeSecretKey,
    epoch: u64,
    message: *const u8,
    message_len: usize,
    signature_out: *mut *mut PQSignature,
) -> PQSigningError {
    if sk.is_null() || message.is_null() || signature_out.is_null() {
        return PQSigningError::InvalidPointer;
    }

    let epoch32 = match epoch_to_u32(epoch) {
        Ok(epoch32) => epoch32,
        Err(err) => return err,
    };
    let message_array = match message_from_ptr(message, message_len) {
        Ok(message_array) => message_array,
        Err(err) => return err,
    };
    let sk = &*(sk as *const PQSignatureSchemeSecretKeyInner);

    if !sk.inner.activation_slots().contains(&epoch32) {
        return PQSigningError::InvalidEpoch;
    }

    let signature = match catch_unwind(AssertUnwindSafe(|| {
        xmss_sign(&sk.inner, epoch32, &message_array)
    })) {
        Ok(Ok(signature)) => signature,
        Ok(Err(XmssSignatureError::EncodingAttemptsExceeded)) => {
            return PQSigningError::EncodingAttemptsExceeded;
        }
        Ok(Err(XmssSignatureError::SlotOutOfRange)) => return PQSigningError::InvalidEpoch,
        Err(_) => return PQSigningError::UnknownError,
    };

    let signature_wrapper = Box::new(PQSignatureInner {
        inner: Box::new(signature),
    });
    *signature_out = Box::into_raw(signature_wrapper) as *mut PQSignature;
    PQSigningError::Success
}

#[no_mangle]
pub unsafe extern "C" fn pq_verify(
    pk: *const PQSignatureSchemePublicKey,
    epoch: u64,
    message: *const u8,
    message_len: usize,
    signature: *const PQSignature,
) -> c_int {
    if pk.is_null() || message.is_null() || signature.is_null() {
        return -1;
    }

    let epoch32 = match epoch_to_u32(epoch) {
        Ok(epoch32) => epoch32,
        Err(_) => return -3,
    };
    let message_array = match message_from_ptr(message, message_len) {
        Ok(message_array) => message_array,
        Err(PQSigningError::InvalidMessageLength) => return -2,
        Err(_) => return -1,
    };

    let pk = &*(pk as *const PQSignatureSchemePublicKeyInner);
    let signature = &*(signature as *const PQSignatureInner);

    if xmss_verify(&pk.inner, epoch32, &message_array, &signature.inner).is_ok() {
        1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn pq_verify_ssz(
    pubkey_bytes: *const u8,
    pubkey_len: usize,
    epoch: u64,
    message: *const u8,
    message_len: usize,
    signature_bytes: *const u8,
    signature_len: usize,
) -> c_int {
    if pubkey_bytes.is_null() || message.is_null() || signature_bytes.is_null() {
        return -1;
    }
    if pubkey_len != PUBLIC_KEY_SIZE {
        return -7;
    }

    let epoch32 = match epoch_to_u32(epoch) {
        Ok(epoch32) => epoch32,
        Err(_) => return -3,
    };
    let message_array = match message_from_ptr(message, message_len) {
        Ok(message_array) => message_array,
        Err(PQSigningError::InvalidMessageLength) => return -2,
        Err(_) => return -1,
    };

    let pubkey_bytes = slice::from_raw_parts(pubkey_bytes, pubkey_len);
    let signature_bytes = slice::from_raw_parts(signature_bytes, signature_len);
    let signature_bytes = match normalize_signature_bytes(signature_bytes) {
        Ok(signature_bytes) => signature_bytes,
        Err(_) => return -8,
    };

    let public_key = match PublicKeyType::from_ssz_bytes(pubkey_bytes) {
        Ok(public_key) => public_key,
        Err(_) => return -5,
    };
    let signature = match SignatureType::from_ssz_bytes(signature_bytes) {
        Ok(signature) => signature,
        Err(_) => return -6,
    };

    if xmss_verify(&public_key, epoch32, &message_array, &signature).is_ok() {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn pq_error_description(error: PQSigningError) -> *mut c_char {
    let description = match error {
        PQSigningError::Success => "Success",
        PQSigningError::EncodingAttemptsExceeded => "Encoding attempts exceeded",
        PQSigningError::InvalidPointer => "Invalid pointer",
        PQSigningError::InvalidMessageLength => "Invalid message length",
        PQSigningError::InvalidEpoch => "Invalid epoch",
        PQSigningError::UnknownError => "Unknown error",
    };

    CString::new(description).unwrap().into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn pq_secret_key_serialize(
    sk: *const PQSignatureSchemeSecretKey,
    buffer: *mut u8,
    buffer_len: usize,
    written_len: *mut usize,
) -> PQSigningError {
    if sk.is_null() {
        return PQSigningError::InvalidPointer;
    }

    let sk = &*(sk as *const PQSignatureSchemeSecretKeyInner);
    let bytes = match postcard::to_allocvec(&sk.inner) {
        Ok(bytes) => bytes,
        Err(_) => return PQSigningError::UnknownError,
    };
    write_bytes_to_buffer(&bytes, buffer, buffer_len, written_len)
}

#[no_mangle]
pub unsafe extern "C" fn pq_secret_key_deserialize(
    buffer: *const u8,
    buffer_len: usize,
    sk_out: *mut *mut PQSignatureSchemeSecretKey,
) -> PQSigningError {
    if buffer.is_null() || sk_out.is_null() {
        return PQSigningError::InvalidPointer;
    }

    let buffer_slice = slice::from_raw_parts(buffer, buffer_len);
    let secret_key = match postcard::from_bytes::<SecretKeyType>(buffer_slice) {
        Ok(secret_key) => secret_key,
        Err(_) => return PQSigningError::UnknownError,
    };

    let secret_key_wrapper = Box::new(PQSignatureSchemeSecretKeyInner {
        inner: Box::new(secret_key),
    });
    *sk_out = Box::into_raw(secret_key_wrapper) as *mut PQSignatureSchemeSecretKey;
    PQSigningError::Success
}

#[no_mangle]
pub unsafe extern "C" fn pq_secret_key_from_json(
    json: *const u8,
    json_len: usize,
    sk_out: *mut *mut PQSignatureSchemeSecretKey,
) -> PQSigningError {
    if json.is_null() || sk_out.is_null() || json_len == 0 {
        return PQSigningError::InvalidPointer;
    }

    let json_slice = slice::from_raw_parts(json, json_len);
    let json_str = match std::str::from_utf8(json_slice) {
        Ok(json_str) => json_str,
        Err(_) => return PQSigningError::UnknownError,
    };
    let secret_key = match serde_json::from_str::<SecretKeyType>(json_str) {
        Ok(secret_key) => secret_key,
        Err(_) => return PQSigningError::UnknownError,
    };

    let secret_key_wrapper = Box::new(PQSignatureSchemeSecretKeyInner {
        inner: Box::new(secret_key),
    });
    *sk_out = Box::into_raw(secret_key_wrapper) as *mut PQSignatureSchemeSecretKey;
    PQSigningError::Success
}

#[no_mangle]
pub unsafe extern "C" fn pq_public_key_serialize(
    pk: *const PQSignatureSchemePublicKey,
    buffer: *mut u8,
    buffer_len: usize,
    written_len: *mut usize,
) -> PQSigningError {
    if pk.is_null() {
        return PQSigningError::InvalidPointer;
    }

    let pk = &*(pk as *const PQSignatureSchemePublicKeyInner);
    write_bytes_to_buffer(&pk.inner.as_ssz_bytes(), buffer, buffer_len, written_len)
}

#[no_mangle]
pub unsafe extern "C" fn pq_public_key_deserialize(
    buffer: *const u8,
    buffer_len: usize,
    pk_out: *mut *mut PQSignatureSchemePublicKey,
) -> PQSigningError {
    if buffer.is_null() || pk_out.is_null() {
        return PQSigningError::InvalidPointer;
    }

    let buffer_slice = slice::from_raw_parts(buffer, buffer_len);
    let public_key = match PublicKeyType::from_ssz_bytes(buffer_slice) {
        Ok(public_key) => public_key,
        Err(_) => return PQSigningError::UnknownError,
    };

    let public_key_wrapper = Box::new(PQSignatureSchemePublicKeyInner {
        inner: Box::new(public_key),
    });
    *pk_out = Box::into_raw(public_key_wrapper) as *mut PQSignatureSchemePublicKey;
    PQSigningError::Success
}

#[no_mangle]
pub unsafe extern "C" fn pq_public_key_from_json(
    json: *const u8,
    json_len: usize,
    pk_out: *mut *mut PQSignatureSchemePublicKey,
) -> PQSigningError {
    if json.is_null() || pk_out.is_null() || json_len == 0 {
        return PQSigningError::InvalidPointer;
    }

    let json_slice = slice::from_raw_parts(json, json_len);
    let json_str = match std::str::from_utf8(json_slice) {
        Ok(json_str) => json_str,
        Err(_) => return PQSigningError::UnknownError,
    };
    let public_key = match serde_json::from_str::<PublicKeyType>(json_str) {
        Ok(public_key) => public_key,
        Err(_) => return PQSigningError::UnknownError,
    };

    let public_key_wrapper = Box::new(PQSignatureSchemePublicKeyInner {
        inner: Box::new(public_key),
    });
    *pk_out = Box::into_raw(public_key_wrapper) as *mut PQSignatureSchemePublicKey;
    PQSigningError::Success
}

#[no_mangle]
pub unsafe extern "C" fn pq_signature_serialize(
    signature: *const PQSignature,
    buffer: *mut u8,
    buffer_len: usize,
    written_len: *mut usize,
) -> PQSigningError {
    if signature.is_null() {
        return PQSigningError::InvalidPointer;
    }

    let signature = &*(signature as *const PQSignatureInner);
    write_bytes_to_buffer(
        &signature.inner.as_ssz_bytes(),
        buffer,
        buffer_len,
        written_len,
    )
}

#[no_mangle]
pub unsafe extern "C" fn pq_signature_deserialize(
    buffer: *const u8,
    buffer_len: usize,
    signature_out: *mut *mut PQSignature,
) -> PQSigningError {
    if buffer.is_null() || signature_out.is_null() {
        return PQSigningError::InvalidPointer;
    }

    let buffer_slice = slice::from_raw_parts(buffer, buffer_len);
    let signature_bytes = match normalize_signature_bytes(buffer_slice) {
        Ok(signature_bytes) => signature_bytes,
        Err(err) => return err,
    };
    let signature = match SignatureType::from_ssz_bytes(signature_bytes) {
        Ok(signature) => signature,
        Err(_) => return PQSigningError::UnknownError,
    };

    let signature_wrapper = Box::new(PQSignatureInner {
        inner: Box::new(signature),
    });
    *signature_out = Box::into_raw(signature_wrapper) as *mut PQSignature;
    PQSigningError::Success
}

#[no_mangle]
pub unsafe extern "C" fn pq_signature_from_json(
    json: *const u8,
    json_len: usize,
    signature_out: *mut *mut PQSignature,
) -> PQSigningError {
    if json.is_null() || signature_out.is_null() || json_len == 0 {
        return PQSigningError::InvalidPointer;
    }

    let json_slice = slice::from_raw_parts(json, json_len);
    let json_str = match std::str::from_utf8(json_slice) {
        Ok(json_str) => json_str,
        Err(_) => return PQSigningError::UnknownError,
    };
    let signature = match serde_json::from_str::<SignatureType>(json_str) {
        Ok(signature) => signature,
        Err(_) => return PQSigningError::UnknownError,
    };

    let signature_wrapper = Box::new(PQSignatureInner {
        inner: Box::new(signature),
    });
    *signature_out = Box::into_raw(signature_wrapper) as *mut PQSignature;
    PQSigningError::Success
}

#[no_mangle]
pub extern "C" fn pq_xmss_aggregation_setup_prover() {
    clear_last_error();
    if catch_unwind(AssertUnwindSafe(setup_prover)).is_err() {
        set_last_error("leanvm-xmss: prover setup failed");
    }
}

#[no_mangle]
pub extern "C" fn pq_xmss_aggregation_setup_prover_without_arena() {
    clear_last_error();
    if catch_unwind(AssertUnwindSafe(setup_prover_without_arena)).is_err() {
        set_last_error("leanvm-xmss: prover setup failed");
    }
}

#[no_mangle]
pub extern "C" fn pq_xmss_aggregation_setup_verifier() {
    let _ = catch_unwind(AssertUnwindSafe(setup_verifier));
}

unsafe fn aggregate_raw_signatures(
    pubkeys: *const *const PQSignatureSchemePublicKey,
    signatures: *const *const PQSignature,
    count: usize,
    message: *const u8,
    message_len: usize,
    epoch: u64,
    log_inv_rate: usize,
    buffer: *mut u8,
    buffer_len: usize,
    written_len: *mut usize,
    verify_inputs: bool,
) -> PQSigningError {
    clear_last_error();
    if count == 0 {
        return PQSigningError::UnknownError;
    }

    if pubkeys.is_null() || signatures.is_null() {
        return PQSigningError::InvalidPointer;
    }

    let epoch32 = match epoch_to_u32(epoch) {
        Ok(epoch32) => epoch32,
        Err(err) => return err,
    };
    let message_array = match message_from_ptr(message, message_len) {
        Ok(message_array) => message_array,
        Err(err) => return err,
    };
    let pubkeys = match collect_public_keys(pubkeys, count) {
        Ok(pubkeys) => pubkeys,
        Err(err) => return err,
    };
    let signatures = match collect_signatures(signatures, count) {
        Ok(signatures) => signatures,
        Err(err) => return err,
    };
    let mut raw_xmss = Vec::with_capacity(count);
    for (pubkey, signature) in pubkeys.into_iter().zip(signatures.into_iter()) {
        if verify_inputs && xmss_verify(&pubkey, epoch32, &message_array, &signature).is_err() {
            return PQSigningError::UnknownError;
        }
        raw_xmss.push((pubkey, signature));
    }

    let aggregated_bytes = match run_proving_phase_then(
        || {
            let children: [TypeOneMultiSignature; 0] = [];
            aggregate_type_1(&children, raw_xmss, message_array, epoch32, log_inv_rate)
        },
        |aggregated| aggregated.to_bytes_without_pubkeys(),
    ) {
        Ok(Ok(aggregated_bytes)) => aggregated_bytes,
        Ok(Err(err)) => return aggregation_error("aggregate_type_1", err),
        Err(_) => return PQSigningError::UnknownError,
    };

    write_bytes_to_buffer(&aggregated_bytes, buffer, buffer_len, written_len)
}

#[no_mangle]
pub unsafe extern "C" fn pq_aggregate_signatures(
    pubkeys: *const *const PQSignatureSchemePublicKey,
    signatures: *const *const PQSignature,
    count: usize,
    message: *const u8,
    message_len: usize,
    epoch: u64,
    log_inv_rate: usize,
    buffer: *mut u8,
    buffer_len: usize,
    written_len: *mut usize,
) -> PQSigningError {
    aggregate_raw_signatures(
        pubkeys,
        signatures,
        count,
        message,
        message_len,
        epoch,
        log_inv_rate,
        buffer,
        buffer_len,
        written_len,
        true,
    )
}

#[no_mangle]
pub unsafe extern "C" fn pq_aggregate_signatures_unverified(
    pubkeys: *const *const PQSignatureSchemePublicKey,
    signatures: *const *const PQSignature,
    count: usize,
    message: *const u8,
    message_len: usize,
    epoch: u64,
    log_inv_rate: usize,
    buffer: *mut u8,
    buffer_len: usize,
    written_len: *mut usize,
) -> PQSigningError {
    aggregate_raw_signatures(
        pubkeys,
        signatures,
        count,
        message,
        message_len,
        epoch,
        log_inv_rate,
        buffer,
        buffer_len,
        written_len,
        false,
    )
}

#[no_mangle]
pub unsafe extern "C" fn pq_aggregate_signatures_recursive(
    children: *const PQAggregatedSignatureChild,
    child_count: usize,
    raw_xmss: *const PQRawXmssSignature,
    raw_xmss_count: usize,
    message: *const u8,
    message_len: usize,
    epoch: u64,
    log_inv_rate: usize,
    buffer: *mut u8,
    buffer_len: usize,
    written_len: *mut usize,
) -> PQSigningError {
    clear_last_error();
    aggregate_signatures_impl(
        children,
        child_count,
        raw_xmss,
        raw_xmss_count,
        message,
        message_len,
        epoch,
        log_inv_rate,
        buffer,
        buffer_len,
        written_len,
        true,
    )
}

#[no_mangle]
pub unsafe extern "C" fn pq_aggregate_signatures_recursive_unverified(
    children: *const PQAggregatedSignatureChild,
    child_count: usize,
    raw_xmss: *const PQRawXmssSignature,
    raw_xmss_count: usize,
    message: *const u8,
    message_len: usize,
    epoch: u64,
    log_inv_rate: usize,
    buffer: *mut u8,
    buffer_len: usize,
    written_len: *mut usize,
) -> PQSigningError {
    clear_last_error();
    aggregate_signatures_impl(
        children,
        child_count,
        raw_xmss,
        raw_xmss_count,
        message,
        message_len,
        epoch,
        log_inv_rate,
        buffer,
        buffer_len,
        written_len,
        false,
    )
}

#[no_mangle]
pub unsafe extern "C" fn pq_verify_aggregated_signatures(
    pubkeys: *const *const PQSignatureSchemePublicKey,
    count: usize,
    message: *const u8,
    message_len: usize,
    agg_bytes: *const u8,
    agg_len: usize,
    epoch: u64,
) -> c_int {
    if pubkeys.is_null() || message.is_null() || agg_bytes.is_null() {
        return -1;
    }

    let epoch32 = match epoch_to_u32(epoch) {
        Ok(epoch32) => epoch32,
        Err(_) => return -3,
    };
    let message_array = match message_from_ptr(message, message_len) {
        Ok(message_array) => message_array,
        Err(PQSigningError::InvalidMessageLength) => return -2,
        Err(_) => return -1,
    };
    let pubkeys = match collect_public_keys(pubkeys, count) {
        Ok(pubkeys) => pubkeys,
        Err(_) => return -4,
    };
    let agg_bytes = slice::from_raw_parts(agg_bytes, agg_len);
    let aggregated = match TypeOneMultiSignature::from_bytes_without_pubkeys(agg_bytes, pubkeys) {
        Some(aggregated) => aggregated,
        None => return -5,
    };
    if aggregated.info.core.message != message_array {
        return 0;
    }
    if aggregated.info.core.slot != epoch32 {
        return 0;
    }

    match verify_type_1(&aggregated) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn pq_merge_many_type_1(
    entries: *const PQAggregatedSignatureChild,
    entry_count: usize,
    log_inv_rate: usize,
    buffer: *mut u8,
    buffer_len: usize,
    written_len: *mut usize,
) -> PQSigningError {
    clear_last_error();
    if buffer.is_null() || written_len.is_null() {
        return PQSigningError::InvalidPointer;
    }
    if entry_count == 0 || entries.is_null() {
        return PQSigningError::InvalidPointer;
    }

    let type1_entries = match collect_type1_entries(entries, entry_count) {
        Ok(type1_entries) => type1_entries,
        Err(err) => return err,
    };

    let type2_bytes = match run_proving_phase_then(
        || merge_many_type_1(type1_entries, log_inv_rate),
        |type2| type2.to_bytes_without_pubkeys(),
    ) {
        Ok(Ok(type2_bytes)) => type2_bytes,
        Ok(Err(err)) => return aggregation_error("merge_many_type_1", err),
        Err(_) => return PQSigningError::UnknownError,
    };

    write_bytes_to_buffer(&type2_bytes, buffer, buffer_len, written_len)
}

#[no_mangle]
pub unsafe extern "C" fn pq_verify_type_2_with_messages(
    components: *const PQTypeTwoComponent,
    component_count: usize,
    bindings: *const PQTypeTwoMessageBinding,
    binding_count: usize,
    type2_bytes: *const u8,
    type2_len: usize,
) -> c_int {
    if components.is_null() || bindings.is_null() || type2_bytes.is_null() {
        return -1;
    }
    if component_count != binding_count {
        return -2;
    }

    let pks_per_component = match collect_type2_components(components, component_count) {
        Ok(pks) => pks,
        Err(_) => return -3,
    };
    let expected = match collect_type2_message_bindings(bindings, binding_count) {
        Ok(expected) => expected,
        Err(_) => return -4,
    };
    let sig_bytes = slice::from_raw_parts(type2_bytes, type2_len);
    let type2 =
        match TypeTwoMultiSignature::from_bytes_without_pubkeys(sig_bytes, pks_per_component) {
            Some(type2) => type2,
            None => return -5,
        };
    if type2.info.len() != expected.len() {
        return -6;
    }
    for (info, (message, epoch)) in type2.info.iter().zip(expected.iter()) {
        if info.core.message != *message || info.core.slot != *epoch {
            return 0;
        }
    }

    match verify_type_2(&type2) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn pq_split_type_2_by_message(
    components: *const PQTypeTwoComponent,
    component_count: usize,
    type2_bytes: *const u8,
    type2_len: usize,
    message: *const u8,
    message_len: usize,
    log_inv_rate: usize,
    buffer: *mut u8,
    buffer_len: usize,
    written_len: *mut usize,
) -> PQSigningError {
    clear_last_error();
    if components.is_null()
        || type2_bytes.is_null()
        || message.is_null()
        || buffer.is_null()
        || written_len.is_null()
    {
        return PQSigningError::InvalidPointer;
    }

    let message_array = match message_from_ptr(message, message_len) {
        Ok(message_array) => message_array,
        Err(err) => return err,
    };
    let pks_per_component = match collect_type2_components(components, component_count) {
        Ok(pks) => pks,
        Err(err) => return err,
    };
    let sig_bytes = slice::from_raw_parts(type2_bytes, type2_len);
    let type2 =
        match TypeTwoMultiSignature::from_bytes_without_pubkeys(sig_bytes, pks_per_component) {
            Some(type2) => type2,
            None => return PQSigningError::UnknownError,
        };

    let Some(message_index) = type2
        .info
        .iter()
        .position(|info| info.core.message == message_array)
    else {
        return PQSigningError::UnknownError;
    };
    let type1_bytes = match run_proving_phase_then(
        || split_multi_message_aggregate(type2, message_index, log_inv_rate),
        |type1| type1.to_bytes_without_pubkeys(),
    ) {
        Ok(Ok(type1_bytes)) => type1_bytes,
        Ok(Err(err)) => return aggregation_error("split_multi_message_aggregate", err),
        Err(_) => return PQSigningError::UnknownError,
    };

    write_bytes_to_buffer(&type1_bytes, buffer, buffer_len, written_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_drop_wipes_nested_allocations() {
        let before = WIPED_ALLOCATION_COUNT.load(Ordering::Relaxed);
        {
            let _wipe_guard = WipeDeallocationGuard::new();
            drop(Box::new(vec![0xabu8; 64]));
        }
        let after = WIPED_ALLOCATION_COUNT.load(Ordering::Relaxed);
        assert!(after >= before + 2);
    }

    #[test]
    fn test_exported_main_sizes() {
        assert_eq!(PUBLIC_KEY_SIZE, 32);
        assert_eq!(SIGNATURE_SIZE, 1208);
        assert_eq!(pq_get_public_key_size(), PUBLIC_KEY_SIZE);
        assert_eq!(pq_get_signature_size(), SIGNATURE_SIZE);
    }

    #[test]
    fn test_normalize_signature_bytes_accepts_zero_padding() {
        let mut padded = vec![0u8; SIGNATURE_SIZE + 16];
        padded[..SIGNATURE_SIZE].fill(0xAB);
        assert_eq!(
            normalize_signature_bytes(&padded).unwrap(),
            &padded[..SIGNATURE_SIZE]
        );
    }

    #[test]
    #[ignore = "production-parameter XMSS key generation is expensive in debug builds"]
    fn test_key_gen_sign_verify() {
        unsafe {
            let mut pk: *mut PQSignatureSchemePublicKey = ptr::null_mut();
            let mut sk: *mut PQSignatureSchemeSecretKey = ptr::null_mut();

            let result = pq_key_gen(0, 100, &mut pk, &mut sk);
            assert_eq!(result, PQSigningError::Success);
            assert!(!pk.is_null());
            assert!(!sk.is_null());

            let message = [0u8; MESSAGE_LENGTH];
            let mut signature: *mut PQSignature = ptr::null_mut();
            let sign_result = pq_sign(sk, 10, message.as_ptr(), MESSAGE_LENGTH, &mut signature);
            assert_eq!(sign_result, PQSigningError::Success);
            assert!(!signature.is_null());

            let verify_result = pq_verify(pk, 10, message.as_ptr(), MESSAGE_LENGTH, signature);
            assert_eq!(verify_result, 1);

            pq_signature_free(signature);
            pq_public_key_free(pk);
            pq_secret_key_free(sk);
        }
    }

    #[test]
    #[ignore = "production-parameter XMSS key generation is expensive in debug builds"]
    fn test_signature_size_matches_main_encoding() {
        unsafe {
            let mut pk: *mut PQSignatureSchemePublicKey = ptr::null_mut();
            let mut sk: *mut PQSignatureSchemeSecretKey = ptr::null_mut();
            assert_eq!(
                pq_key_gen(0, 100, &mut pk, &mut sk),
                PQSigningError::Success
            );

            let message = [7u8; MESSAGE_LENGTH];
            let mut signature: *mut PQSignature = ptr::null_mut();
            assert_eq!(
                pq_sign(sk, 10, message.as_ptr(), MESSAGE_LENGTH, &mut signature),
                PQSigningError::Success
            );

            let mut serialized = vec![0u8; SIGNATURE_SIZE];
            let mut written = 0usize;
            assert_eq!(
                pq_signature_serialize(
                    signature,
                    serialized.as_mut_ptr(),
                    serialized.len(),
                    &mut written
                ),
                PQSigningError::Success
            );
            assert_eq!(written, SIGNATURE_SIZE);

            pq_signature_free(signature);
            pq_public_key_free(pk);
            pq_secret_key_free(sk);
        }
    }

    #[test]
    #[ignore = "production-parameter XMSS key generation is expensive in debug builds"]
    fn test_signature_deserialize_accepts_zero_padding() {
        unsafe {
            let mut pk: *mut PQSignatureSchemePublicKey = ptr::null_mut();
            let mut sk: *mut PQSignatureSchemeSecretKey = ptr::null_mut();
            assert_eq!(
                pq_key_gen(0, 100, &mut pk, &mut sk),
                PQSigningError::Success
            );

            let message = [3u8; MESSAGE_LENGTH];
            let mut signature: *mut PQSignature = ptr::null_mut();
            assert_eq!(
                pq_sign(sk, 10, message.as_ptr(), MESSAGE_LENGTH, &mut signature),
                PQSigningError::Success
            );

            let mut serialized = vec![0u8; SIGNATURE_SIZE + 16];
            let mut written = 0usize;
            assert_eq!(
                pq_signature_serialize(
                    signature,
                    serialized.as_mut_ptr(),
                    SIGNATURE_SIZE,
                    &mut written
                ),
                PQSigningError::Success
            );
            assert_eq!(written, SIGNATURE_SIZE);

            let mut deserialized: *mut PQSignature = ptr::null_mut();
            assert_eq!(
                pq_signature_deserialize(serialized.as_ptr(), serialized.len(), &mut deserialized),
                PQSigningError::Success
            );
            assert_eq!(
                pq_verify(pk, 10, message.as_ptr(), MESSAGE_LENGTH, deserialized),
                1
            );

            let mut pubkey_bytes = [0u8; PUBLIC_KEY_SIZE];
            let mut pubkey_written = 0usize;
            assert_eq!(
                pq_public_key_serialize(
                    pk,
                    pubkey_bytes.as_mut_ptr(),
                    pubkey_bytes.len(),
                    &mut pubkey_written
                ),
                PQSigningError::Success
            );
            assert_eq!(pubkey_written, PUBLIC_KEY_SIZE);
            assert_eq!(
                pq_verify_ssz(
                    pubkey_bytes.as_ptr(),
                    PUBLIC_KEY_SIZE,
                    10,
                    message.as_ptr(),
                    MESSAGE_LENGTH,
                    serialized.as_ptr(),
                    serialized.len(),
                ),
                1
            );

            pq_signature_free(deserialized);
            pq_signature_free(signature);
            pq_public_key_free(pk);
            pq_secret_key_free(sk);
        }
    }

    #[test]
    #[ignore = "expensive aggregation proof generation"]
    fn test_recursive_aggregation_smoke() {
        unsafe {
            pq_xmss_aggregation_setup_prover();

            let message = [9u8; MESSAGE_LENGTH];
            let mut pubkeys = Vec::new();
            let mut secrets = Vec::new();
            let mut signatures = Vec::new();

            for _ in 0..3 {
                let mut pk: *mut PQSignatureSchemePublicKey = ptr::null_mut();
                let mut sk: *mut PQSignatureSchemeSecretKey = ptr::null_mut();
                assert_eq!(
                    pq_key_gen(0, 100, &mut pk, &mut sk),
                    PQSigningError::Success
                );

                let mut signature: *mut PQSignature = ptr::null_mut();
                assert_eq!(
                    pq_sign(sk, 10, message.as_ptr(), MESSAGE_LENGTH, &mut signature),
                    PQSigningError::Success
                );

                pubkeys.push(pk);
                secrets.push(sk);
                signatures.push(signature);
            }

            let child_one_pubkeys = [pubkeys[0] as *const PQSignatureSchemePublicKey];
            let child_one_signatures = [signatures[0] as *const PQSignature];
            let mut child_one_bytes = vec![0u8; 512 * 1024];
            let mut child_one_written = 0usize;
            assert_eq!(
                pq_aggregate_signatures(
                    child_one_pubkeys.as_ptr(),
                    child_one_signatures.as_ptr(),
                    child_one_pubkeys.len(),
                    message.as_ptr(),
                    MESSAGE_LENGTH,
                    10,
                    DEFAULT_LOG_INV_RATE,
                    child_one_bytes.as_mut_ptr(),
                    child_one_bytes.len(),
                    &mut child_one_written,
                ),
                PQSigningError::Success
            );
            child_one_bytes.truncate(child_one_written);

            let child_two_pubkeys = [pubkeys[1] as *const PQSignatureSchemePublicKey];
            let child_two_signatures = [signatures[1] as *const PQSignature];
            let mut child_two_bytes = vec![0u8; 512 * 1024];
            let mut child_two_written = 0usize;
            assert_eq!(
                pq_aggregate_signatures(
                    child_two_pubkeys.as_ptr(),
                    child_two_signatures.as_ptr(),
                    child_two_pubkeys.len(),
                    message.as_ptr(),
                    MESSAGE_LENGTH,
                    10,
                    DEFAULT_LOG_INV_RATE,
                    child_two_bytes.as_mut_ptr(),
                    child_two_bytes.len(),
                    &mut child_two_written,
                ),
                PQSigningError::Success
            );
            child_two_bytes.truncate(child_two_written);

            let children = [
                PQAggregatedSignatureChild {
                    pubkeys: child_one_pubkeys.as_ptr(),
                    pubkey_count: child_one_pubkeys.len(),
                    agg_bytes: child_one_bytes.as_ptr(),
                    agg_len: child_one_bytes.len(),
                },
                PQAggregatedSignatureChild {
                    pubkeys: child_two_pubkeys.as_ptr(),
                    pubkey_count: child_two_pubkeys.len(),
                    agg_bytes: child_two_bytes.as_ptr(),
                    agg_len: child_two_bytes.len(),
                },
            ];
            let raw_xmss = [PQRawXmssSignature {
                pubkey: pubkeys[2] as *const PQSignatureSchemePublicKey,
                signature: signatures[2] as *const PQSignature,
            }];
            let final_pubkeys = [
                pubkeys[0] as *const PQSignatureSchemePublicKey,
                pubkeys[1] as *const PQSignatureSchemePublicKey,
                pubkeys[2] as *const PQSignatureSchemePublicKey,
            ];

            let mut final_bytes = vec![0u8; 1024 * 1024];
            let mut final_written = 0usize;
            assert_eq!(
                pq_aggregate_signatures_recursive(
                    children.as_ptr(),
                    children.len(),
                    raw_xmss.as_ptr(),
                    raw_xmss.len(),
                    message.as_ptr(),
                    MESSAGE_LENGTH,
                    10,
                    DEFAULT_LOG_INV_RATE,
                    final_bytes.as_mut_ptr(),
                    final_bytes.len(),
                    &mut final_written,
                ),
                PQSigningError::Success
            );
            final_bytes.truncate(final_written);

            pq_xmss_aggregation_setup_verifier();
            assert_eq!(
                pq_verify_aggregated_signatures(
                    final_pubkeys.as_ptr(),
                    final_pubkeys.len(),
                    message.as_ptr(),
                    MESSAGE_LENGTH,
                    final_bytes.as_ptr(),
                    final_bytes.len(),
                    10,
                ),
                1
            );

            for signature in signatures {
                pq_signature_free(signature);
            }
            for pubkey in pubkeys {
                pq_public_key_free(pubkey);
            }
            for secret in secrets {
                pq_secret_key_free(secret);
            }
        }
    }
}
