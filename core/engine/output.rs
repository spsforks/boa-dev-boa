pub mod array_buffer {
    //! Boa's implementation of ECMAScript's global `ArrayBuffer` and `SharedArrayBuffer` objects
    //!
    //! More information:
    //!  - [ECMAScript reference][spec]
    //!  - [MDN documentation][mdn]
    //!
    //! [spec]: https://tc39.es/ecma262/#sec-arraybuffer-objects
    //! [mdn]: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/ArrayBuffer
    #![deny(unsafe_op_in_unsafe_fn)]
    #![deny(clippy::undocumented_unsafe_blocks)]
    pub(crate) mod shared {
        #![allow(unstable_name_collisions)]
        use std::{alloc, sync::{atomic::Ordering, Arc}};
        use boa_profiler::Profiler;
        use portable_atomic::{AtomicU8, AtomicUsize};
        use boa_gc::{Finalize, Trace};
        use sptr::Strict;
        use crate::{
            builtins::{
                Array, BuiltInBuilder, BuiltInConstructor, BuiltInObject, IntrinsicObject,
            },
            context::intrinsics::{Intrinsics, StandardConstructor, StandardConstructors},
            js_string, object::internal_methods::get_prototype_from_constructor,
            property::Attribute, realm::Realm, string::StaticJsStrings, Context, JsArgs,
            JsData, JsNativeError, JsObject, JsResult, JsString, JsSymbol, JsValue,
        };
        use super::{get_max_byte_len, utils::copy_shared_to_shared};
        /// The internal representation of a `SharedArrayBuffer` object.
        ///
        /// This struct implements `Send` and `Sync`, meaning it can be shared between threads
        /// running different JS code at the same time.
        pub struct SharedArrayBuffer {
            #[unsafe_ignore_trace]
            data: Arc<Inner>,
        }
        #[automatically_derived]
        impl ::core::fmt::Debug for SharedArrayBuffer {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                ::core::fmt::Formatter::debug_struct_field1_finish(
                    f,
                    "SharedArrayBuffer",
                    "data",
                    &&self.data,
                )
            }
        }
        #[automatically_derived]
        impl ::core::clone::Clone for SharedArrayBuffer {
            #[inline]
            fn clone(&self) -> SharedArrayBuffer {
                SharedArrayBuffer {
                    data: ::core::clone::Clone::clone(&self.data),
                }
            }
        }
        const _: () = {
            unsafe impl ::boa_gc::Trace for SharedArrayBuffer {
                #[inline]
                unsafe fn trace(&self, tracer: &mut ::boa_gc::Tracer) {
                    #[expect(dead_code)]
                    let mut mark = |it: &dyn ::boa_gc::Trace| {
                        unsafe {
                            ::boa_gc::Trace::trace(it, tracer);
                        }
                    };
                    match *self {
                        SharedArrayBuffer { .. } => {}
                    }
                }
                #[inline]
                unsafe fn trace_non_roots(&self) {
                    #[expect(dead_code)]
                    fn mark<T: ::boa_gc::Trace + ?Sized>(it: &T) {
                        unsafe {
                            ::boa_gc::Trace::trace_non_roots(it);
                        }
                    }
                    match *self {
                        SharedArrayBuffer { .. } => {}
                    }
                }
                #[inline]
                fn run_finalizer(&self) {
                    ::boa_gc::Finalize::finalize(self);
                    #[expect(dead_code)]
                    fn mark<T: ::boa_gc::Trace + ?Sized>(it: &T) {
                        unsafe {
                            ::boa_gc::Trace::run_finalizer(it);
                        }
                    }
                    match *self {
                        SharedArrayBuffer { .. } => {}
                    }
                }
            }
        };
        const _: () = {
            impl ::core::ops::Drop for SharedArrayBuffer {
                #[expect(clippy::inline_always)]
                #[inline(always)]
                fn drop(&mut self) {
                    if ::boa_gc::finalizer_safe() {
                        ::boa_gc::Finalize::finalize(self);
                    }
                }
            }
        };
        const _: () = {
            impl ::boa_gc::Finalize for SharedArrayBuffer {}
        };
        const _: () = {
            impl ::boa_engine::JsData for SharedArrayBuffer {}
        };
        struct Inner {
            buffer: Box<[AtomicU8]>,
            current_len: Option<AtomicUsize>,
        }
        #[automatically_derived]
        impl ::core::fmt::Debug for Inner {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                ::core::fmt::Formatter::debug_struct_field2_finish(
                    f,
                    "Inner",
                    "buffer",
                    &self.buffer,
                    "current_len",
                    &&self.current_len,
                )
            }
        }
        #[automatically_derived]
        impl ::core::default::Default for Inner {
            #[inline]
            fn default() -> Inner {
                Inner {
                    buffer: ::core::default::Default::default(),
                    current_len: ::core::default::Default::default(),
                }
            }
        }
        impl SharedArrayBuffer {
            /// Creates a `SharedArrayBuffer` with an empty buffer.
            #[must_use]
            pub fn empty() -> Self {
                Self { data: Arc::default() }
            }
            /// Gets the length of this `SharedArrayBuffer`.
            pub(crate) fn len(&self, ordering: Ordering) -> usize {
                self.data
                    .current_len
                    .as_ref()
                    .map_or_else(|| self.data.buffer.len(), |len| len.load(ordering))
            }
            /// Gets the inner bytes of this `SharedArrayBuffer`.
            pub(crate) fn bytes(&self, ordering: Ordering) -> &[AtomicU8] {
                &self.data.buffer[..self.len(ordering)]
            }
            /// Gets the inner data of the buffer without accessing the current atomic length.
            #[track_caller]
            pub(crate) fn bytes_with_len(&self, len: usize) -> &[AtomicU8] {
                &self.data.buffer[..len]
            }
            /// Gets a pointer to the internal shared buffer.
            pub(crate) fn as_ptr(&self) -> *const AtomicU8 {
                (*self.data.buffer).as_ptr()
            }
            pub(crate) fn is_fixed_len(&self) -> bool {
                self.data.current_len.is_none()
            }
        }
        impl IntrinsicObject for SharedArrayBuffer {
            fn init(realm: &Realm) {
                let _timer = Profiler::global()
                    .start_event(std::any::type_name::<Self>(), "init");
                let flag_attributes = Attribute::CONFIGURABLE
                    | Attribute::NON_ENUMERABLE;
                let get_species = BuiltInBuilder::callable(realm, Self::get_species)
                    .name({
                        const LITERAL: &crate::string::StaticJsString = &crate::string::StaticJsString::new(
                            ::boa_engine::string::JsStr::latin1(
                                [
                                    103,
                                    101,
                                    116,
                                    32,
                                    91,
                                    83,
                                    121,
                                    109,
                                    98,
                                    111,
                                    108,
                                    46,
                                    115,
                                    112,
                                    101,
                                    99,
                                    105,
                                    101,
                                    115,
                                    93,
                                ]
                                    .as_slice(),
                            ),
                        );
                        crate::string::JsString::from_static_js_string(LITERAL)
                    })
                    .build();
                let get_byte_length = BuiltInBuilder::callable(
                        realm,
                        Self::get_byte_length,
                    )
                    .name({
                        const LITERAL: &crate::string::StaticJsString = &crate::string::StaticJsString::new(
                            ::boa_engine::string::JsStr::latin1(
                                [
                                    103,
                                    101,
                                    116,
                                    32,
                                    98,
                                    121,
                                    116,
                                    101,
                                    76,
                                    101,
                                    110,
                                    103,
                                    116,
                                    104,
                                ]
                                    .as_slice(),
                            ),
                        );
                        crate::string::JsString::from_static_js_string(LITERAL)
                    })
                    .build();
                let get_growable = BuiltInBuilder::callable(realm, Self::get_growable)
                    .name({
                        const LITERAL: &crate::string::StaticJsString = &crate::string::StaticJsString::new(
                            ::boa_engine::string::JsStr::latin1(
                                [103, 101, 116, 32, 103, 114, 111, 119, 97, 98, 108, 101]
                                    .as_slice(),
                            ),
                        );
                        crate::string::JsString::from_static_js_string(LITERAL)
                    })
                    .build();
                let get_max_byte_length = BuiltInBuilder::callable(
                        realm,
                        Self::get_max_byte_length,
                    )
                    .name({
                        const LITERAL: &crate::string::StaticJsString = &crate::string::StaticJsString::new(
                            ::boa_engine::string::JsStr::latin1(
                                [
                                    103,
                                    101,
                                    116,
                                    32,
                                    109,
                                    97,
                                    120,
                                    66,
                                    121,
                                    116,
                                    101,
                                    76,
                                    101,
                                    110,
                                    103,
                                    116,
                                    104,
                                ]
                                    .as_slice(),
                            ),
                        );
                        crate::string::JsString::from_static_js_string(LITERAL)
                    })
                    .build();
                BuiltInBuilder::from_standard_constructor::<Self>(realm)
                    .static_accessor(
                        JsSymbol::species(),
                        Some(get_species),
                        None,
                        Attribute::CONFIGURABLE,
                    )
                    .accessor(
                        {
                            const LITERAL: &crate::string::StaticJsString = &crate::string::StaticJsString::new(
                                ::boa_engine::string::JsStr::latin1(
                                    [98, 121, 116, 101, 76, 101, 110, 103, 116, 104].as_slice(),
                                ),
                            );
                            crate::string::JsString::from_static_js_string(LITERAL)
                        },
                        Some(get_byte_length),
                        None,
                        flag_attributes,
                    )
                    .accessor(
                        {
                            const LITERAL: &crate::string::StaticJsString = &crate::string::StaticJsString::new(
                                ::boa_engine::string::JsStr::latin1(
                                    [103, 114, 111, 119, 97, 98, 108, 101].as_slice(),
                                ),
                            );
                            crate::string::JsString::from_static_js_string(LITERAL)
                        },
                        Some(get_growable),
                        None,
                        flag_attributes,
                    )
                    .accessor(
                        {
                            const LITERAL: &crate::string::StaticJsString = &crate::string::StaticJsString::new(
                                ::boa_engine::string::JsStr::latin1(
                                    [
                                        109,
                                        97,
                                        120,
                                        66,
                                        121,
                                        116,
                                        101,
                                        76,
                                        101,
                                        110,
                                        103,
                                        116,
                                        104,
                                    ]
                                        .as_slice(),
                                ),
                            );
                            crate::string::JsString::from_static_js_string(LITERAL)
                        },
                        Some(get_max_byte_length),
                        None,
                        flag_attributes,
                    )
                    .method(
                        Self::slice,
                        {
                            const LITERAL: &crate::string::StaticJsString = &crate::string::StaticJsString::new(
                                ::boa_engine::string::JsStr::latin1(
                                    [115, 108, 105, 99, 101].as_slice(),
                                ),
                            );
                            crate::string::JsString::from_static_js_string(LITERAL)
                        },
                        2,
                    )
                    .method(
                        Self::grow,
                        {
                            const LITERAL: &crate::string::StaticJsString = &crate::string::StaticJsString::new(
                                ::boa_engine::string::JsStr::latin1(
                                    [103, 114, 111, 119].as_slice(),
                                ),
                            );
                            crate::string::JsString::from_static_js_string(LITERAL)
                        },
                        1,
                    )
                    .property(
                        JsSymbol::to_string_tag(),
                        Self::NAME,
                        Attribute::READONLY | Attribute::NON_ENUMERABLE
                            | Attribute::CONFIGURABLE,
                    )
                    .build();
            }
            fn get(intrinsics: &Intrinsics) -> JsObject {
                Self::STANDARD_CONSTRUCTOR(intrinsics.constructors()).constructor()
            }
        }
        impl BuiltInObject for SharedArrayBuffer {
            const NAME: JsString = StaticJsStrings::SHARED_ARRAY_BUFFER;
        }
        impl BuiltInConstructor for SharedArrayBuffer {
            const LENGTH: usize = 1;
            const STANDARD_CONSTRUCTOR: fn(
                &StandardConstructors,
            ) -> &StandardConstructor = StandardConstructors::shared_array_buffer;
            /// `25.1.3.1 SharedArrayBuffer ( length [ , options ] )`
            ///
            /// More information:
            ///  - [ECMAScript reference][spec]
            ///
            /// [spec]: https://tc39.es/ecma262/#sec-sharedarraybuffer-constructor
            fn constructor(
                new_target: &JsValue,
                args: &[JsValue],
                context: &mut Context,
            ) -> JsResult<JsValue> {
                if new_target.is_undefined() {
                    return Err(
                        JsNativeError::typ()
                            .with_message(
                                "ArrayBuffer.constructor called with undefined new target",
                            )
                            .into(),
                    );
                }
                let byte_len = args.get_or_undefined(0).to_index(context)?;
                let max_byte_len = get_max_byte_len(args.get_or_undefined(1), context)?;
                Ok(
                    Self::allocate(new_target, byte_len, max_byte_len, context)?
                        .upcast()
                        .into(),
                )
            }
        }
        impl SharedArrayBuffer {
            /// `get SharedArrayBuffer [ @@species ]`
            ///
            /// More information:
            ///  - [ECMAScript reference][spec]
            ///
            /// [spec]: https://tc39.es/ecma262/#sec-sharedarraybuffer-@@species
            
            fn get_species(
                this: &JsValue,
                _: &[JsValue],
                _: &mut Context,
            ) -> JsResult<JsValue> {
                Ok(this.clone())
            }
            /// `get SharedArrayBuffer.prototype.byteLength`
            ///
            /// More information:
            ///  - [ECMAScript reference][spec]
            ///
            /// [spec]: https://tc39.es/ecma262/#sec-get-sharedarraybuffer.prototype.bytelength
            pub(crate) fn get_byte_length(
                this: &JsValue,
                _args: &[JsValue],
                _: &mut Context,
            ) -> JsResult<JsValue> {
                let buf = this
                    .as_object()
                    .and_then(JsObject::downcast_ref::<Self>)
                    .ok_or_else(|| {
                        JsNativeError::typ()
                            .with_message(
                                "SharedArrayBuffer.byteLength called with invalid value",
                            )
                    })?;
                let len = buf.bytes(Ordering::SeqCst).len() as u64;
                Ok(len.into())
            }
            /// [`get SharedArrayBuffer.prototype.growable`][spec].
            ///
            /// [spec]: https://tc39.es/ecma262/#sec-get-sharedarraybuffer.prototype.growable
            pub(crate) fn get_growable(
                this: &JsValue,
                _args: &[JsValue],
                _context: &mut Context,
            ) -> JsResult<JsValue> {
                let buf = this
                    .as_object()
                    .and_then(JsObject::downcast_ref::<Self>)
                    .ok_or_else(|| {
                        JsNativeError::typ()
                            .with_message(
                                "get SharedArrayBuffer.growable called with invalid `this`",
                            )
                    })?;
                Ok(JsValue::from(!buf.is_fixed_len()))
            }
            /// [`get SharedArrayBuffer.prototype.maxByteLength`][spec].
            ///
            /// [spec]: https://tc39.es/ecma262/#sec-get-sharedarraybuffer.prototype.maxbytelength
            pub(crate) fn get_max_byte_length(
                this: &JsValue,
                _args: &[JsValue],
                _context: &mut Context,
            ) -> JsResult<JsValue> {
                let buf = this
                    .as_object()
                    .and_then(JsObject::downcast_ref::<Self>)
                    .ok_or_else(|| {
                        JsNativeError::typ()
                            .with_message(
                                "get SharedArrayBuffer.maxByteLength called with invalid value",
                            )
                    })?;
                Ok(buf.data.buffer.len().into())
            }
            /// [`SharedArrayBuffer.prototype.grow ( newLength )`][spec].
            ///
            /// [spec]: https://tc39.es/ecma262/sec-sharedarraybuffer.prototype.grow
            pub(crate) fn grow(
                this: &JsValue,
                args: &[JsValue],
                context: &mut Context,
            ) -> JsResult<JsValue> {
                let Some(buf) = this
                    .as_object()
                    .and_then(|o| o.clone().downcast::<Self>().ok()) else {
                    return Err(
                        JsNativeError::typ()
                            .with_message(
                                "SharedArrayBuffer.grow called with non-object value",
                            )
                            .into(),
                    );
                };
                if buf.borrow().data.is_fixed_len() {
                    return Err(
                        JsNativeError::typ()
                            .with_message(
                                "SharedArrayBuffer.grow: cannot grow a fixed-length buffer",
                            )
                            .into(),
                    );
                }
                let new_byte_len = args.get_or_undefined(0).to_index(context)?;
                let buf = buf.borrow();
                let buf = &buf.data;
                if new_byte_len > buf.data.buffer.len() as u64 {
                    return Err(
                        JsNativeError::range()
                            .with_message(
                                "SharedArrayBuffer.grow: new length cannot be bigger than `maxByteLength`",
                            )
                            .into(),
                    );
                }
                let new_byte_len = new_byte_len as usize;
                let atomic_len = buf
                    .data
                    .current_len
                    .as_ref()
                    .expect("already checked that the buffer is not fixed-length");
                atomic_len
                    .fetch_update(
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                        |prev_byte_len| {
                            (prev_byte_len <= new_byte_len).then_some(new_byte_len)
                        },
                    )
                    .map_err(|_| {
                        JsNativeError::range()
                            .with_message(
                                "SharedArrayBuffer.grow: failed to grow buffer to new length",
                            )
                    })?;
                Ok(JsValue::undefined())
            }
            /// `SharedArrayBuffer.prototype.slice ( start, end )`
            ///
            /// More information:
            ///  - [ECMAScript reference][spec]
            ///
            /// [spec]: https://tc39.es/ecma262/#sec-sharedarraybuffer.prototype.slice
            fn slice(
                this: &JsValue,
                args: &[JsValue],
                context: &mut Context,
            ) -> JsResult<JsValue> {
                let buf = this
                    .as_object()
                    .and_then(|o| o.clone().downcast::<Self>().ok())
                    .ok_or_else(|| {
                        JsNativeError::typ()
                            .with_message(
                                "SharedArrayBuffer.slice called with invalid `this` value",
                            )
                    })?;
                let len = buf.borrow().data.len(Ordering::SeqCst);
                let first = Array::get_relative_start(
                    context,
                    args.get_or_undefined(0),
                    len as u64,
                )?;
                let final_ = Array::get_relative_end(
                    context,
                    args.get_or_undefined(1),
                    len as u64,
                )?;
                let new_len = final_.saturating_sub(first);
                let ctor = buf
                    .clone()
                    .upcast()
                    .species_constructor(
                        StandardConstructors::shared_array_buffer,
                        context,
                    )?;
                let new = ctor.construct(&[new_len.into()], Some(&ctor), context)?;
                {
                    let buf = buf.borrow();
                    let buf = &buf.data;
                    let new = new
                        .downcast_ref::<Self>()
                        .ok_or_else(|| {
                            JsNativeError::typ()
                                .with_message(
                                    "SharedArrayBuffer constructor returned invalid object",
                                )
                        })?;
                    if std::ptr::eq(buf.as_ptr(), new.as_ptr()) {
                        return Err(
                            JsNativeError::typ()
                                .with_message(
                                    "cannot reuse the same SharedArrayBuffer for a slice operation",
                                )
                                .into(),
                        );
                    }
                    if (new.len(Ordering::SeqCst) as u64) < new_len {
                        return Err(
                            JsNativeError::typ()
                                .with_message(
                                    "invalid size of constructed SharedArrayBuffer",
                                )
                                .into(),
                        );
                    }
                    let first = first as usize;
                    let new_len = new_len as usize;
                    let from_buf = &buf.bytes_with_len(len)[first..];
                    let to_buf = new;
                    if true {
                        if !(from_buf.len() >= new_len) {
                            ::core::panicking::panic(
                                "assertion failed: from_buf.len() >= new_len",
                            )
                        }
                    }
                    unsafe {
                        copy_shared_to_shared(
                            from_buf.as_ptr(),
                            to_buf.as_ptr(),
                            new_len,
                        )
                    }
                }
                Ok(new.into())
            }
            /// `AllocateSharedArrayBuffer ( constructor, byteLength [ , maxByteLength ] )`
            ///
            /// More information:
            ///  - [ECMAScript reference][spec]
            ///
            /// [spec]: https://tc39.es/ecma262/#sec-allocatesharedarraybuffer
            pub(crate) fn allocate(
                constructor: &JsValue,
                byte_len: u64,
                max_byte_len: Option<u64>,
                context: &mut Context,
            ) -> JsResult<JsObject<SharedArrayBuffer>> {
                if let Some(max_byte_len) = max_byte_len {
                    if byte_len > max_byte_len {
                        return Err(
                            JsNativeError::range()
                                .with_message(
                                    "`length` cannot be bigger than `maxByteLength`",
                                )
                                .into(),
                        );
                    }
                }
                let prototype = get_prototype_from_constructor(
                    constructor,
                    StandardConstructors::shared_array_buffer,
                    context,
                )?;
                let alloc_len = max_byte_len.unwrap_or(byte_len);
                let block = create_shared_byte_data_block(alloc_len, context)?;
                let current_len = max_byte_len
                    .map(|_| AtomicUsize::new(byte_len as usize));
                let obj = JsObject::new(
                    context.root_shape(),
                    prototype,
                    Self {
                        data: Arc::new(Inner {
                            buffer: block,
                            current_len,
                        }),
                    },
                );
                Ok(obj)
            }
        }
        /// [`CreateSharedByteDataBlock ( size )`][spec] abstract operation.
        ///
        /// Creates a new `Arc<Vec<AtomicU8>>` that can be used as a backing buffer for a [`SharedArrayBuffer`].
        ///
        /// For more information, check the [spec][spec].
        ///
        /// [spec]: https://tc39.es/ecma262/#sec-createsharedbytedatablock
        pub(crate) fn create_shared_byte_data_block(
            size: u64,
            context: &mut Context,
        ) -> JsResult<Box<[AtomicU8]>> {
            if size > context.host_hooks().max_buffer_size(context) {
                return Err(
                    JsNativeError::range()
                        .with_message(
                            "cannot allocate a buffer that exceeds the maximum buffer size"
                                .to_string(),
                        )
                        .into(),
                );
            }
            let size = size
                .try_into()
                .map_err(|e| {
                    JsNativeError::range()
                        .with_message(
                            ::alloc::__export::must_use({
                                let res = ::alloc::fmt::format(
                                    format_args!("couldn\'t allocate the data block: {0}", e),
                                );
                                res
                            }),
                        )
                })?;
            if size == 0 {
                return Ok(Box::default());
            }
            let layout = alloc::Layout::array::<AtomicU8>(size)
                .map_err(|e| {
                    JsNativeError::range()
                        .with_message(
                            ::alloc::__export::must_use({
                                let res = ::alloc::fmt::format(
                                    format_args!("couldn\'t allocate the data block: {0}", e),
                                );
                                res
                            }),
                        )
                })?;
            let ptr: *mut AtomicU8 = unsafe { alloc::alloc_zeroed(layout).cast() };
            if ptr.is_null() {
                return Err(
                    JsNativeError::range()
                        .with_message("memory allocator failed to allocate buffer")
                        .into(),
                );
            }
            let buffer = unsafe {
                Box::from_raw(std::slice::from_raw_parts_mut(ptr, size))
            };
            match (&(buffer.as_ptr().addr() % align_of::<u64>()), &0) {
                (left_val, right_val) => {
                    if !(*left_val == *right_val) {
                        let kind = ::core::panicking::AssertKind::Eq;
                        ::core::panicking::assert_failed(
                            kind,
                            &*left_val,
                            &*right_val,
                            ::core::option::Option::None,
                        );
                    }
                }
            };
            Ok(buffer)
        }
    }
    pub(crate) mod utils {
        #![allow(unstable_name_collisions)]
        use std::{ptr, slice::SliceIndex, sync::atomic::Ordering};
        use portable_atomic::AtomicU8;
        use crate::{
            builtins::typed_array::{
                ClampedU8, Element, TypedArrayElement, TypedArrayKind,
            },
            Context, JsObject, JsResult,
        };
        use super::ArrayBuffer;
        pub(crate) enum BytesConstPtr {
            Bytes(*const u8),
            AtomicBytes(*const AtomicU8),
        }
        #[automatically_derived]
        impl ::core::clone::Clone for BytesConstPtr {
            #[inline]
            fn clone(&self) -> BytesConstPtr {
                let _: ::core::clone::AssertParamIsClone<*const u8>;
                let _: ::core::clone::AssertParamIsClone<*const AtomicU8>;
                *self
            }
        }
        #[automatically_derived]
        impl ::core::marker::Copy for BytesConstPtr {}
        pub(crate) enum BytesMutPtr {
            Bytes(*mut u8),
            AtomicBytes(*const AtomicU8),
        }
        #[automatically_derived]
        impl ::core::clone::Clone for BytesMutPtr {
            #[inline]
            fn clone(&self) -> BytesMutPtr {
                let _: ::core::clone::AssertParamIsClone<*mut u8>;
                let _: ::core::clone::AssertParamIsClone<*const AtomicU8>;
                *self
            }
        }
        #[automatically_derived]
        impl ::core::marker::Copy for BytesMutPtr {}
        pub(crate) enum SliceRef<'a> {
            Slice(&'a [u8]),
            AtomicSlice(&'a [AtomicU8]),
        }
        #[automatically_derived]
        impl<'a> ::core::fmt::Debug for SliceRef<'a> {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                match self {
                    SliceRef::Slice(__self_0) => {
                        ::core::fmt::Formatter::debug_tuple_field1_finish(
                            f,
                            "Slice",
                            &__self_0,
                        )
                    }
                    SliceRef::AtomicSlice(__self_0) => {
                        ::core::fmt::Formatter::debug_tuple_field1_finish(
                            f,
                            "AtomicSlice",
                            &__self_0,
                        )
                    }
                }
            }
        }
        #[automatically_derived]
        impl<'a> ::core::clone::Clone for SliceRef<'a> {
            #[inline]
            fn clone(&self) -> SliceRef<'a> {
                let _: ::core::clone::AssertParamIsClone<&'a [u8]>;
                let _: ::core::clone::AssertParamIsClone<&'a [AtomicU8]>;
                *self
            }
        }
        #[automatically_derived]
        impl<'a> ::core::marker::Copy for SliceRef<'a> {}
        impl SliceRef<'_> {
            /// Gets the byte length of this `SliceRef`.
            pub(crate) fn len(&self) -> usize {
                match self {
                    Self::Slice(buf) => buf.len(),
                    Self::AtomicSlice(buf) => buf.len(),
                }
            }
            /// Gets a subslice of this `SliceRef`.
            pub(crate) fn subslice<I>(&self, index: I) -> SliceRef<'_>
            where
                I: SliceIndex<[u8], Output = [u8]>
                    + SliceIndex<[AtomicU8], Output = [AtomicU8]>,
            {
                match self {
                    Self::Slice(buffer) => {
                        SliceRef::Slice(buffer.get(index).expect("index out of bounds"))
                    }
                    Self::AtomicSlice(buffer) => {
                        SliceRef::AtomicSlice(
                            buffer.get(index).expect("index out of bounds"),
                        )
                    }
                }
            }
            /// Gets the starting address of this `SliceRef`.
            #[cfg(debug_assertions)]
            pub(crate) fn addr(&self) -> usize {
                use sptr::Strict;
                match self {
                    Self::Slice(buf) => buf.as_ptr().addr(),
                    Self::AtomicSlice(buf) => buf.as_ptr().addr(),
                }
            }
            /// Gets a pointer to the underlying slice.
            pub(crate) fn as_ptr(&self) -> BytesConstPtr {
                match self {
                    SliceRef::Slice(s) => BytesConstPtr::Bytes(s.as_ptr()),
                    SliceRef::AtomicSlice(s) => BytesConstPtr::AtomicBytes(s.as_ptr()),
                }
            }
            /// [`GetValueFromBuffer ( arrayBuffer, byteIndex, type, isTypedArray, order [ , isLittleEndian ] )`][spec]
            ///
            /// The start offset is determined by the input buffer instead of a `byteIndex` parameter.
            ///
            /// # Safety
            ///
            /// - There must be enough bytes in `buffer` to read an element from an array with type `TypedArrayKind`.
            /// - `buffer` must be aligned to the alignment of said element.
            ///
            /// [spec]: https://tc39.es/ecma262/#sec-getvaluefrombuffer
            pub(crate) unsafe fn get_value(
                &self,
                kind: TypedArrayKind,
                order: Ordering,
            ) -> TypedArrayElement {
                unsafe fn read_elem<T: Element>(
                    buffer: SliceRef<'_>,
                    order: Ordering,
                ) -> T {
                    #[cfg(debug_assertions)]
                    {
                        if !(buffer.len() >= size_of::<T>()) {
                            ::core::panicking::panic(
                                "assertion failed: buffer.len() >= size_of::<T>()",
                            )
                        }
                        match (&(buffer.addr() % align_of::<T>()), &0) {
                            (left_val, right_val) => {
                                if !(*left_val == *right_val) {
                                    let kind = ::core::panicking::AssertKind::Eq;
                                    ::core::panicking::assert_failed(
                                        kind,
                                        &*left_val,
                                        &*right_val,
                                        ::core::option::Option::None,
                                    );
                                }
                            }
                        };
                    }
                    unsafe { T::read(buffer).load(order) }
                }
                let buffer = *self;
                unsafe {
                    match kind {
                        TypedArrayKind::Int8 => read_elem::<i8>(buffer, order).into(),
                        TypedArrayKind::Uint8 => read_elem::<u8>(buffer, order).into(),
                        TypedArrayKind::Uint8Clamped => {
                            read_elem::<ClampedU8>(buffer, order).into()
                        }
                        TypedArrayKind::Int16 => read_elem::<i16>(buffer, order).into(),
                        TypedArrayKind::Uint16 => read_elem::<u16>(buffer, order).into(),
                        TypedArrayKind::Int32 => read_elem::<i32>(buffer, order).into(),
                        TypedArrayKind::Uint32 => read_elem::<u32>(buffer, order).into(),
                        TypedArrayKind::BigInt64 => {
                            read_elem::<i64>(buffer, order).into()
                        }
                        TypedArrayKind::BigUint64 => {
                            read_elem::<u64>(buffer, order).into()
                        }
                        TypedArrayKind::Float32 => read_elem::<f32>(buffer, order).into(),
                        TypedArrayKind::Float64 => read_elem::<f64>(buffer, order).into(),
                    }
                }
            }
            /// [`CloneArrayBuffer ( srcBuffer, srcByteOffset, srcLength )`][spec]
            ///
            /// [spec]: https://tc39.es/ecma262/#sec-clonearraybuffer
            pub(crate) fn clone(
                &self,
                context: &mut Context,
            ) -> JsResult<JsObject<ArrayBuffer>> {
                let target_buffer = ArrayBuffer::allocate(
                    &context
                        .realm()
                        .intrinsics()
                        .constructors()
                        .array_buffer()
                        .constructor()
                        .into(),
                    self.len() as u64,
                    None,
                    context,
                )?;
                {
                    let mut target_buffer = target_buffer.borrow_mut();
                    let target_block = target_buffer
                        .data
                        .bytes_mut()
                        .expect("ArrayBuffer cannot be detached here");
                    unsafe {
                        memcpy(
                            self.as_ptr(),
                            BytesMutPtr::Bytes(target_block.as_mut_ptr()),
                            self.len(),
                        );
                    }
                }
                Ok(target_buffer)
            }
        }
        impl<'a> From<&'a [u8]> for SliceRef<'a> {
            fn from(value: &'a [u8]) -> Self {
                Self::Slice(value)
            }
        }
        impl<'a> From<&'a [AtomicU8]> for SliceRef<'a> {
            fn from(value: &'a [AtomicU8]) -> Self {
                Self::AtomicSlice(value)
            }
        }
        pub(crate) enum SliceRefMut<'a> {
            Slice(&'a mut [u8]),
            AtomicSlice(&'a [AtomicU8]),
        }
        #[automatically_derived]
        impl<'a> ::core::fmt::Debug for SliceRefMut<'a> {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                match self {
                    SliceRefMut::Slice(__self_0) => {
                        ::core::fmt::Formatter::debug_tuple_field1_finish(
                            f,
                            "Slice",
                            &__self_0,
                        )
                    }
                    SliceRefMut::AtomicSlice(__self_0) => {
                        ::core::fmt::Formatter::debug_tuple_field1_finish(
                            f,
                            "AtomicSlice",
                            &__self_0,
                        )
                    }
                }
            }
        }
        impl SliceRefMut<'_> {
            /// Gets the byte length of this `SliceRefMut`.
            pub(crate) fn len(&self) -> usize {
                match self {
                    Self::Slice(buf) => buf.len(),
                    Self::AtomicSlice(buf) => buf.len(),
                }
            }
            /// Gets a mutable subslice of this `SliceRefMut`.
            pub(crate) fn subslice_mut<I>(&mut self, index: I) -> SliceRefMut<'_>
            where
                I: SliceIndex<[u8], Output = [u8]>
                    + SliceIndex<[AtomicU8], Output = [AtomicU8]>,
            {
                match self {
                    Self::Slice(buffer) => {
                        SliceRefMut::Slice(
                            buffer.get_mut(index).expect("index out of bounds"),
                        )
                    }
                    Self::AtomicSlice(buffer) => {
                        SliceRefMut::AtomicSlice(
                            buffer.get(index).expect("index out of bounds"),
                        )
                    }
                }
            }
            /// Gets the starting address of this `SliceRefMut`.
            #[cfg(debug_assertions)]
            pub(crate) fn addr(&self) -> usize {
                use sptr::Strict;
                match self {
                    Self::Slice(buf) => buf.as_ptr().addr(),
                    Self::AtomicSlice(buf) => buf.as_ptr().addr(),
                }
            }
            /// Gets a pointer to the underlying slice.
            pub(crate) fn as_ptr(&mut self) -> BytesMutPtr {
                match self {
                    Self::Slice(s) => BytesMutPtr::Bytes(s.as_mut_ptr()),
                    Self::AtomicSlice(s) => BytesMutPtr::AtomicBytes(s.as_ptr()),
                }
            }
            /// `25.1.2.12 SetValueInBuffer ( arrayBuffer, byteIndex, type, value, isTypedArray, order [ , isLittleEndian ] )`
            ///
            /// The start offset is determined by the input buffer instead of a `byteIndex` parameter.
            ///
            /// # Safety
            ///
            /// - There must be enough bytes in `buffer` to write the `TypedArrayElement`.
            /// - `buffer` must be aligned to the alignment of the `TypedArrayElement`.
            ///
            /// # Panics
            ///
            /// - Panics if the type of `value` is not equal to the content of `kind`.
            ///
            /// More information:
            ///  - [ECMAScript reference][spec]
            ///
            /// [spec]: https://tc39.es/ecma262/#sec-setvalueinbuffer
            pub(crate) unsafe fn set_value(
                &mut self,
                value: TypedArrayElement,
                order: Ordering,
            ) {
                unsafe fn write_elem<T: Element>(
                    buffer: SliceRefMut<'_>,
                    value: T,
                    order: Ordering,
                ) {
                    #[cfg(debug_assertions)]
                    {
                        if !(buffer.len() >= size_of::<T>()) {
                            ::core::panicking::panic(
                                "assertion failed: buffer.len() >= size_of::<T>()",
                            )
                        }
                        match (&(buffer.addr() % align_of::<T>()), &0) {
                            (left_val, right_val) => {
                                if !(*left_val == *right_val) {
                                    let kind = ::core::panicking::AssertKind::Eq;
                                    ::core::panicking::assert_failed(
                                        kind,
                                        &*left_val,
                                        &*right_val,
                                        ::core::option::Option::None,
                                    );
                                }
                            }
                        };
                    }
                    unsafe {
                        T::read_mut(buffer).store(value, order);
                    }
                }
                let buffer = match self {
                    SliceRefMut::Slice(buf) => SliceRefMut::Slice(buf),
                    SliceRefMut::AtomicSlice(buf) => SliceRefMut::AtomicSlice(buf),
                };
                unsafe {
                    match value {
                        TypedArrayElement::Int8(e) => write_elem(buffer, e, order),
                        TypedArrayElement::Uint8(e) => write_elem(buffer, e, order),
                        TypedArrayElement::Uint8Clamped(e) => {
                            write_elem(buffer, e, order)
                        }
                        TypedArrayElement::Int16(e) => write_elem(buffer, e, order),
                        TypedArrayElement::Uint16(e) => write_elem(buffer, e, order),
                        TypedArrayElement::Int32(e) => write_elem(buffer, e, order),
                        TypedArrayElement::Uint32(e) => write_elem(buffer, e, order),
                        TypedArrayElement::BigInt64(e) => write_elem(buffer, e, order),
                        TypedArrayElement::BigUint64(e) => write_elem(buffer, e, order),
                        TypedArrayElement::Float32(e) => write_elem(buffer, e, order),
                        TypedArrayElement::Float64(e) => write_elem(buffer, e, order),
                    }
                }
            }
        }
        impl<'a> From<&'a mut [u8]> for SliceRefMut<'a> {
            fn from(value: &'a mut [u8]) -> Self {
                Self::Slice(value)
            }
        }
        impl<'a> From<&'a [AtomicU8]> for SliceRefMut<'a> {
            fn from(value: &'a [AtomicU8]) -> Self {
                Self::AtomicSlice(value)
            }
        }
        /// Copies `count` bytes from `src` into `dest` using atomic relaxed loads and stores.
        ///
        /// # Safety
        ///
        /// - Both `src` and `dest` must have at least `count` bytes to read and write,
        ///   respectively.
        pub(super) unsafe fn copy_shared_to_shared(
            src: *const AtomicU8,
            dest: *const AtomicU8,
            count: usize,
        ) {
            for i in 0..count {
                unsafe {
                    (*dest.add(i))
                        .store((*src.add(i)).load(Ordering::Relaxed), Ordering::Relaxed);
                }
            }
        }
        /// Copies `count` bytes backwards from `src` into `dest` using atomic relaxed loads and stores.
        ///
        /// # Safety
        ///
        /// - Both `src` and `dest` must have at least `count` bytes to read and write,
        ///   respectively.
        unsafe fn copy_shared_to_shared_backwards(
            src: *const AtomicU8,
            dest: *const AtomicU8,
            count: usize,
        ) {
            for i in (0..count).rev() {
                unsafe {
                    (*dest.add(i))
                        .store((*src.add(i)).load(Ordering::Relaxed), Ordering::Relaxed);
                }
            }
        }
        /// Copies `count` bytes from the buffer `src` into the buffer `dest`, using the atomic ordering
        /// `Ordering::Relaxed` if any of the buffers are atomic.
        ///
        /// # Safety
        ///
        /// - Both `src` and `dest` must have at least `count` bytes to read and write, respectively.
        /// - The region of memory referenced by `src` must not overlap with the region of memory
        ///   referenced by `dest`.
        pub(crate) unsafe fn memcpy(
            src: BytesConstPtr,
            dest: BytesMutPtr,
            count: usize,
        ) {
            match (src, dest) {
                (BytesConstPtr::Bytes(src), BytesMutPtr::Bytes(dest)) => {
                    unsafe {
                        ptr::copy_nonoverlapping(src, dest, count);
                    }
                }
                (BytesConstPtr::Bytes(src), BytesMutPtr::AtomicBytes(dest)) => {
                    unsafe {
                        for i in 0..count {
                            (*dest.add(i)).store(*src.add(i), Ordering::Relaxed);
                        }
                    }
                }
                (BytesConstPtr::AtomicBytes(src), BytesMutPtr::Bytes(dest)) => {
                    unsafe {
                        for i in 0..count {
                            *dest.add(i) = (*src.add(i)).load(Ordering::Relaxed);
                        }
                    }
                }
                (BytesConstPtr::AtomicBytes(src), BytesMutPtr::AtomicBytes(dest)) => {
                    unsafe {
                        copy_shared_to_shared(src, dest, count);
                    }
                }
            }
        }
        /// Copies `count` bytes from the position `from` to the position `to` in `buffer`.
        ///
        /// # Safety
        ///
        /// - `ptr` must be valid from the offset `ptr + from` for `count` reads of bytes.
        /// - `ptr` must be valid from the offset `ptr + to` for `count` writes of bytes.
        pub(crate) unsafe fn memmove(
            ptr: BytesMutPtr,
            from: usize,
            to: usize,
            count: usize,
        ) {
            match ptr {
                BytesMutPtr::Bytes(ptr) => {
                    unsafe {
                        let src = ptr.add(from);
                        let dest = ptr.add(to);
                        ptr::copy(src, dest, count);
                    }
                }
                BytesMutPtr::AtomicBytes(ptr) => {
                    unsafe {
                        let src = ptr.add(from);
                        let dest = ptr.add(to);
                        if src < dest {
                            copy_shared_to_shared_backwards(src, dest, count);
                        } else {
                            copy_shared_to_shared(src, dest, count);
                        }
                    }
                }
            }
        }
    }
    use std::ops::{Deref, DerefMut};
    pub use shared::SharedArrayBuffer;
    use std::sync::atomic::Ordering;
    use crate::{
        builtins::BuiltInObject,
        context::intrinsics::{Intrinsics, StandardConstructor, StandardConstructors},
        error::JsNativeError, js_string,
        object::{internal_methods::get_prototype_from_constructor, JsObject, Object},
        property::Attribute, realm::Realm, string::StaticJsStrings, symbol::JsSymbol,
        Context, JsArgs, JsData, JsResult, JsString, JsValue,
    };
    use boa_gc::{Finalize, GcRef, GcRefMut, Trace};
    use boa_profiler::Profiler;
    use self::utils::{SliceRef, SliceRefMut};
    use super::{
        typed_array::TypedArray, Array, BuiltInBuilder, BuiltInConstructor, DataView,
        IntrinsicObject,
    };
    pub(crate) enum BufferRef<B, S> {
        Buffer(B),
        SharedBuffer(S),
    }
    #[automatically_derived]
    impl<B: ::core::fmt::Debug, S: ::core::fmt::Debug> ::core::fmt::Debug
    for BufferRef<B, S> {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match self {
                BufferRef::Buffer(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "Buffer",
                        &__self_0,
                    )
                }
                BufferRef::SharedBuffer(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "SharedBuffer",
                        &__self_0,
                    )
                }
            }
        }
    }
    #[automatically_derived]
    impl<B: ::core::clone::Clone, S: ::core::clone::Clone> ::core::clone::Clone
    for BufferRef<B, S> {
        #[inline]
        fn clone(&self) -> BufferRef<B, S> {
            match self {
                BufferRef::Buffer(__self_0) => {
                    BufferRef::Buffer(::core::clone::Clone::clone(__self_0))
                }
                BufferRef::SharedBuffer(__self_0) => {
                    BufferRef::SharedBuffer(::core::clone::Clone::clone(__self_0))
                }
            }
        }
    }
    #[automatically_derived]
    impl<B: ::core::marker::Copy, S: ::core::marker::Copy> ::core::marker::Copy
    for BufferRef<B, S> {}
    impl<B, S> BufferRef<B, S>
    where
        B: Deref<Target = ArrayBuffer>,
        S: Deref<Target = SharedArrayBuffer>,
    {
        /// Gets the inner data of the buffer.
        pub(crate) fn bytes(&self, ordering: Ordering) -> Option<SliceRef<'_>> {
            match self {
                Self::Buffer(buf) => buf.deref().bytes().map(SliceRef::Slice),
                Self::SharedBuffer(buf) => {
                    Some(SliceRef::AtomicSlice(buf.deref().bytes(ordering)))
                }
            }
        }
        /// Gets the inner data of the buffer without accessing the current atomic length.
        ///
        /// Returns `None` if the buffer is detached or if the provided `len` is bigger than
        /// the allocated buffer.
        #[track_caller]
        pub(crate) fn bytes_with_len(&self, len: usize) -> Option<SliceRef<'_>> {
            match self {
                Self::Buffer(buf) => buf.deref().bytes_with_len(len).map(SliceRef::Slice),
                Self::SharedBuffer(buf) => {
                    Some(SliceRef::AtomicSlice(buf.deref().bytes_with_len(len)))
                }
            }
        }
        pub(crate) fn is_fixed_len(&self) -> bool {
            match self {
                Self::Buffer(buf) => buf.is_fixed_len(),
                Self::SharedBuffer(buf) => buf.is_fixed_len(),
            }
        }
    }
    pub(crate) enum BufferRefMut<B, S> {
        Buffer(B),
        SharedBuffer(S),
    }
    #[automatically_derived]
    impl<B: ::core::fmt::Debug, S: ::core::fmt::Debug> ::core::fmt::Debug
    for BufferRefMut<B, S> {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match self {
                BufferRefMut::Buffer(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "Buffer",
                        &__self_0,
                    )
                }
                BufferRefMut::SharedBuffer(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "SharedBuffer",
                        &__self_0,
                    )
                }
            }
        }
    }
    impl<B, S> BufferRefMut<B, S>
    where
        B: DerefMut<Target = ArrayBuffer>,
        S: DerefMut<Target = SharedArrayBuffer>,
    {
        pub(crate) fn bytes(&mut self, ordering: Ordering) -> Option<SliceRefMut<'_>> {
            match self {
                Self::Buffer(buf) => buf.deref_mut().bytes_mut().map(SliceRefMut::Slice),
                Self::SharedBuffer(buf) => {
                    Some(SliceRefMut::AtomicSlice(buf.deref_mut().bytes(ordering)))
                }
            }
        }
        /// Gets the mutable inner data of the buffer without accessing the current atomic length.
        ///
        /// Returns `None` if the buffer is detached or if the provided `len` is bigger than
        /// the allocated buffer.
        pub(crate) fn bytes_with_len(&mut self, len: usize) -> Option<SliceRefMut<'_>> {
            match self {
                Self::Buffer(buf) => {
                    buf.deref_mut().bytes_with_len_mut(len).map(SliceRefMut::Slice)
                }
                Self::SharedBuffer(buf) => {
                    Some(SliceRefMut::AtomicSlice(buf.deref_mut().bytes_with_len(len)))
                }
            }
        }
    }
    /// A `JsObject` containing a bytes buffer as its inner data.
    #[boa_gc(unsafe_no_drop)]
    pub(crate) enum BufferObject {
        Buffer(JsObject<ArrayBuffer>),
        SharedBuffer(JsObject<SharedArrayBuffer>),
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for BufferObject {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match self {
                BufferObject::Buffer(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "Buffer",
                        &__self_0,
                    )
                }
                BufferObject::SharedBuffer(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "SharedBuffer",
                        &__self_0,
                    )
                }
            }
        }
    }
    #[automatically_derived]
    impl ::core::clone::Clone for BufferObject {
        #[inline]
        fn clone(&self) -> BufferObject {
            match self {
                BufferObject::Buffer(__self_0) => {
                    BufferObject::Buffer(::core::clone::Clone::clone(__self_0))
                }
                BufferObject::SharedBuffer(__self_0) => {
                    BufferObject::SharedBuffer(::core::clone::Clone::clone(__self_0))
                }
            }
        }
    }
    const _: () = {
        unsafe impl ::boa_gc::Trace for BufferObject {
            #[inline]
            unsafe fn trace(&self, tracer: &mut ::boa_gc::Tracer) {
                #[expect(dead_code)]
                let mut mark = |it: &dyn ::boa_gc::Trace| {
                    unsafe {
                        ::boa_gc::Trace::trace(it, tracer);
                    }
                };
                match *self {
                    BufferObject::Buffer(ref __binding_0) => {
                        ::boa_gc::Trace::trace(__binding_0, tracer)
                    }
                    BufferObject::SharedBuffer(ref __binding_0) => {
                        ::boa_gc::Trace::trace(__binding_0, tracer)
                    }
                }
            }
            #[inline]
            unsafe fn trace_non_roots(&self) {
                #[expect(dead_code)]
                fn mark<T: ::boa_gc::Trace + ?Sized>(it: &T) {
                    unsafe {
                        ::boa_gc::Trace::trace_non_roots(it);
                    }
                }
                match *self {
                    BufferObject::Buffer(ref __binding_0) => mark(__binding_0),
                    BufferObject::SharedBuffer(ref __binding_0) => mark(__binding_0),
                }
            }
            #[inline]
            fn run_finalizer(&self) {
                ::boa_gc::Finalize::finalize(self);
                #[expect(dead_code)]
                fn mark<T: ::boa_gc::Trace + ?Sized>(it: &T) {
                    unsafe {
                        ::boa_gc::Trace::run_finalizer(it);
                    }
                }
                match *self {
                    BufferObject::Buffer(ref __binding_0) => mark(__binding_0),
                    BufferObject::SharedBuffer(ref __binding_0) => mark(__binding_0),
                }
            }
        }
    };
    const _: () = {
        impl ::boa_gc::Finalize for BufferObject {}
    };
    impl From<BufferObject> for JsObject {
        fn from(value: BufferObject) -> Self {
            match value {
                BufferObject::Buffer(buf) => buf.upcast(),
                BufferObject::SharedBuffer(buf) => buf.upcast(),
            }
        }
    }
    impl From<BufferObject> for JsValue {
        fn from(value: BufferObject) -> Self {
            JsValue::from(JsObject::from(value))
        }
    }
    impl BufferObject {
        /// Gets the buffer data of the object.
        #[inline]
        #[must_use]
        pub(crate) fn as_buffer(
            &self,
        ) -> BufferRef<GcRef<'_, ArrayBuffer>, GcRef<'_, SharedArrayBuffer>> {
            match self {
                Self::Buffer(buf) => {
                    BufferRef::Buffer(GcRef::map(buf.borrow(), |o| &o.data))
                }
                Self::SharedBuffer(buf) => {
                    BufferRef::SharedBuffer(GcRef::map(buf.borrow(), |o| &o.data))
                }
            }
        }
        /// Gets the mutable buffer data of the object
        #[inline]
        pub(crate) fn as_buffer_mut(
            &self,
        ) -> BufferRefMut<
            GcRefMut<'_, Object<ArrayBuffer>, ArrayBuffer>,
            GcRefMut<'_, Object<SharedArrayBuffer>, SharedArrayBuffer>,
        > {
            match self {
                Self::Buffer(buf) => {
                    BufferRefMut::Buffer(
                        GcRefMut::map(buf.borrow_mut(), |o| &mut o.data),
                    )
                }
                Self::SharedBuffer(buf) => {
                    BufferRefMut::SharedBuffer(
                        GcRefMut::map(buf.borrow_mut(), |o| &mut o.data),
                    )
                }
            }
        }
        /// Returns `true` if the buffer objects point to the same buffer.
        #[inline]
        pub(crate) fn equals(lhs: &Self, rhs: &Self) -> bool {
            match (lhs, rhs) {
                (BufferObject::Buffer(lhs), BufferObject::Buffer(rhs)) => {
                    JsObject::equals(lhs, rhs)
                }
                (BufferObject::SharedBuffer(lhs), BufferObject::SharedBuffer(rhs)) => {
                    if JsObject::equals(lhs, rhs) {
                        return true;
                    }
                    let lhs = lhs.borrow();
                    let rhs = rhs.borrow();
                    std::ptr::eq(lhs.data.as_ptr(), rhs.data.as_ptr())
                }
                _ => false,
            }
        }
    }
    /// The internal representation of an `ArrayBuffer` object.
    pub struct ArrayBuffer {
        /// The `[[ArrayBufferData]]` internal slot.
        data: Option<Vec<u8>>,
        /// The `[[ArrayBufferMaxByteLength]]` internal slot.
        max_byte_len: Option<u64>,
        /// The `[[ArrayBufferDetachKey]]` internal slot.
        detach_key: JsValue,
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for ArrayBuffer {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field3_finish(
                f,
                "ArrayBuffer",
                "data",
                &self.data,
                "max_byte_len",
                &self.max_byte_len,
                "detach_key",
                &&self.detach_key,
            )
        }
    }
    #[automatically_derived]
    impl ::core::clone::Clone for ArrayBuffer {
        #[inline]
        fn clone(&self) -> ArrayBuffer {
            ArrayBuffer {
                data: ::core::clone::Clone::clone(&self.data),
                max_byte_len: ::core::clone::Clone::clone(&self.max_byte_len),
                detach_key: ::core::clone::Clone::clone(&self.detach_key),
            }
        }
    }
    const _: () = {
        unsafe impl ::boa_gc::Trace for ArrayBuffer {
            #[inline]
            unsafe fn trace(&self, tracer: &mut ::boa_gc::Tracer) {
                #[expect(dead_code)]
                let mut mark = |it: &dyn ::boa_gc::Trace| {
                    unsafe {
                        ::boa_gc::Trace::trace(it, tracer);
                    }
                };
                match *self {
                    ArrayBuffer {
                        data: ref __binding_0,
                        max_byte_len: ref __binding_1,
                        detach_key: ref __binding_2,
                    } => {
                        { ::boa_gc::Trace::trace(__binding_0, tracer) }
                        { ::boa_gc::Trace::trace(__binding_1, tracer) }
                        { ::boa_gc::Trace::trace(__binding_2, tracer) }
                    }
                }
            }
            #[inline]
            unsafe fn trace_non_roots(&self) {
                #[expect(dead_code)]
                fn mark<T: ::boa_gc::Trace + ?Sized>(it: &T) {
                    unsafe {
                        ::boa_gc::Trace::trace_non_roots(it);
                    }
                }
                match *self {
                    ArrayBuffer {
                        data: ref __binding_0,
                        max_byte_len: ref __binding_1,
                        detach_key: ref __binding_2,
                    } => {
                        { mark(__binding_0) }
                        { mark(__binding_1) }
                        { mark(__binding_2) }
                    }
                }
            }
            #[inline]
            fn run_finalizer(&self) {
                ::boa_gc::Finalize::finalize(self);
                #[expect(dead_code)]
                fn mark<T: ::boa_gc::Trace + ?Sized>(it: &T) {
                    unsafe {
                        ::boa_gc::Trace::run_finalizer(it);
                    }
                }
                match *self {
                    ArrayBuffer {
                        data: ref __binding_0,
                        max_byte_len: ref __binding_1,
                        detach_key: ref __binding_2,
                    } => {
                        { mark(__binding_0) }
                        { mark(__binding_1) }
                        { mark(__binding_2) }
                    }
                }
            }
        }
    };
    const _: () = {
        impl ::core::ops::Drop for ArrayBuffer {
            #[expect(clippy::inline_always)]
            #[inline(always)]
            fn drop(&mut self) {
                if ::boa_gc::finalizer_safe() {
                    ::boa_gc::Finalize::finalize(self);
                }
            }
        }
    };
    const _: () = {
        impl ::boa_gc::Finalize for ArrayBuffer {}
    };
    const _: () = {
        impl ::boa_engine::JsData for ArrayBuffer {}
    };
    impl ArrayBuffer {
        pub(crate) fn from_data(data: Vec<u8>, detach_key: JsValue) -> Self {
            Self {
                data: Some(data),
                max_byte_len: None,
                detach_key,
            }
        }
        pub(crate) fn len(&self) -> usize {
            self.data.as_ref().map_or(0, Vec::len)
        }
        pub(crate) fn bytes(&self) -> Option<&[u8]> {
            self.data.as_deref()
        }
        pub(crate) fn bytes_mut(&mut self) -> Option<&mut [u8]> {
            self.data.as_deref_mut()
        }
        pub(crate) fn vec_mut(&mut self) -> Option<&mut Vec<u8>> {
            self.data.as_mut()
        }
        /// Gets the inner bytes of the buffer without accessing the current atomic length.
        #[track_caller]
        pub(crate) fn bytes_with_len(&self, len: usize) -> Option<&[u8]> {
            if let Some(s) = self.data.as_deref() { Some(&s[..len]) } else { None }
        }
        /// Gets the mutable inner bytes of the buffer without accessing the current atomic length.
        #[track_caller]
        pub(crate) fn bytes_with_len_mut(&mut self, len: usize) -> Option<&mut [u8]> {
            if let Some(s) = self.data.as_deref_mut() {
                Some(&mut s[..len])
            } else {
                None
            }
        }
        /// Detaches the inner data of this `ArrayBuffer`, returning the original buffer if still
        /// present.
        ///
        /// # Errors
        ///
        /// Throws an error if the provided detach key is invalid.
        pub fn detach(&mut self, key: &JsValue) -> JsResult<Option<Vec<u8>>> {
            if !JsValue::same_value(&self.detach_key, key) {
                return Err(
                    JsNativeError::typ()
                        .with_message("Cannot detach array buffer with different key")
                        .into(),
                );
            }
            Ok(self.data.take())
        }
        /// `IsDetachedBuffer ( arrayBuffer )`
        ///
        /// More information:
        ///  - [ECMAScript reference][spec]
        ///
        /// [spec]: https://tc39.es/ecma262/#sec-isdetachedbuffer
        pub(crate) const fn is_detached(&self) -> bool {
            self.data.is_none()
        }
        pub(crate) fn is_fixed_len(&self) -> bool {
            self.max_byte_len.is_none()
        }
    }
    impl IntrinsicObject for ArrayBuffer {
        fn init(realm: &Realm) {
            let _timer = Profiler::global()
                .start_event(std::any::type_name::<Self>(), "init");
            let flag_attributes = Attribute::CONFIGURABLE | Attribute::NON_ENUMERABLE;
            let get_species = BuiltInBuilder::callable(realm, Self::get_species)
                .name({
                    const LITERAL: &crate::string::StaticJsString = &crate::string::StaticJsString::new(
                        ::boa_engine::string::JsStr::latin1(
                            [
                                103,
                                101,
                                116,
                                32,
                                91,
                                83,
                                121,
                                109,
                                98,
                                111,
                                108,
                                46,
                                115,
                                112,
                                101,
                                99,
                                105,
                                101,
                                115,
                                93,
                            ]
                                .as_slice(),
                        ),
                    );
                    crate::string::JsString::from_static_js_string(LITERAL)
                })
                .build();
            let get_byte_length = BuiltInBuilder::callable(realm, Self::get_byte_length)
                .name({
                    const LITERAL: &crate::string::StaticJsString = &crate::string::StaticJsString::new(
                        ::boa_engine::string::JsStr::latin1(
                            [
                                103,
                                101,
                                116,
                                32,
                                98,
                                121,
                                116,
                                101,
                                76,
                                101,
                                110,
                                103,
                                116,
                                104,
                            ]
                                .as_slice(),
                        ),
                    );
                    crate::string::JsString::from_static_js_string(LITERAL)
                })
                .build();
            let get_resizable = BuiltInBuilder::callable(realm, Self::get_resizable)
                .name({
                    const LITERAL: &crate::string::StaticJsString = &crate::string::StaticJsString::new(
                        ::boa_engine::string::JsStr::latin1(
                            [
                                103,
                                101,
                                116,
                                32,
                                114,
                                101,
                                115,
                                105,
                                122,
                                97,
                                98,
                                108,
                                101,
                            ]
                                .as_slice(),
                        ),
                    );
                    crate::string::JsString::from_static_js_string(LITERAL)
                })
                .build();
            let get_max_byte_length = BuiltInBuilder::callable(
                    realm,
                    Self::get_max_byte_length,
                )
                .name({
                    const LITERAL: &crate::string::StaticJsString = &crate::string::StaticJsString::new(
                        ::boa_engine::string::JsStr::latin1(
                            [
                                103,
                                101,
                                116,
                                32,
                                109,
                                97,
                                120,
                                66,
                                121,
                                116,
                                101,
                                76,
                                101,
                                110,
                                103,
                                116,
                                104,
                            ]
                                .as_slice(),
                        ),
                    );
                    crate::string::JsString::from_static_js_string(LITERAL)
                })
                .build();
            let builder = BuiltInBuilder::from_standard_constructor::<Self>(realm)
                .static_accessor(
                    JsSymbol::species(),
                    Some(get_species),
                    None,
                    Attribute::CONFIGURABLE,
                )
                .static_method(
                    Self::is_view,
                    {
                        const LITERAL: &crate::string::StaticJsString = &crate::string::StaticJsString::new(
                            ::boa_engine::string::JsStr::latin1(
                                [105, 115, 86, 105, 101, 119].as_slice(),
                            ),
                        );
                        crate::string::JsString::from_static_js_string(LITERAL)
                    },
                    1,
                )
                .accessor(
                    {
                        const LITERAL: &crate::string::StaticJsString = &crate::string::StaticJsString::new(
                            ::boa_engine::string::JsStr::latin1(
                                [98, 121, 116, 101, 76, 101, 110, 103, 116, 104].as_slice(),
                            ),
                        );
                        crate::string::JsString::from_static_js_string(LITERAL)
                    },
                    Some(get_byte_length),
                    None,
                    flag_attributes,
                )
                .accessor(
                    {
                        const LITERAL: &crate::string::StaticJsString = &crate::string::StaticJsString::new(
                            ::boa_engine::string::JsStr::latin1(
                                [114, 101, 115, 105, 122, 97, 98, 108, 101].as_slice(),
                            ),
                        );
                        crate::string::JsString::from_static_js_string(LITERAL)
                    },
                    Some(get_resizable),
                    None,
                    flag_attributes,
                )
                .accessor(
                    {
                        const LITERAL: &crate::string::StaticJsString = &crate::string::StaticJsString::new(
                            ::boa_engine::string::JsStr::latin1(
                                [
                                    109,
                                    97,
                                    120,
                                    66,
                                    121,
                                    116,
                                    101,
                                    76,
                                    101,
                                    110,
                                    103,
                                    116,
                                    104,
                                ]
                                    .as_slice(),
                            ),
                        );
                        crate::string::JsString::from_static_js_string(LITERAL)
                    },
                    Some(get_max_byte_length),
                    None,
                    flag_attributes,
                )
                .method(
                    Self::resize,
                    {
                        const LITERAL: &crate::string::StaticJsString = &crate::string::StaticJsString::new(
                            ::boa_engine::string::JsStr::latin1(
                                [114, 101, 115, 105, 122, 101].as_slice(),
                            ),
                        );
                        crate::string::JsString::from_static_js_string(LITERAL)
                    },
                    1,
                )
                .method(
                    Self::slice,
                    {
                        const LITERAL: &crate::string::StaticJsString = &crate::string::StaticJsString::new(
                            ::boa_engine::string::JsStr::latin1(
                                [115, 108, 105, 99, 101].as_slice(),
                            ),
                        );
                        crate::string::JsString::from_static_js_string(LITERAL)
                    },
                    2,
                )
                .property(
                    JsSymbol::to_string_tag(),
                    Self::NAME,
                    Attribute::READONLY | Attribute::NON_ENUMERABLE
                        | Attribute::CONFIGURABLE,
                );
            builder.build();
        }
        fn get(intrinsics: &Intrinsics) -> JsObject {
            Self::STANDARD_CONSTRUCTOR(intrinsics.constructors()).constructor()
        }
    }
    impl BuiltInObject for ArrayBuffer {
        const NAME: JsString = StaticJsStrings::ARRAY_BUFFER;
    }
    impl BuiltInConstructor for ArrayBuffer {
        const LENGTH: usize = 1;
        const STANDARD_CONSTRUCTOR: fn(&StandardConstructors) -> &StandardConstructor = StandardConstructors::array_buffer;
        /// `ArrayBuffer ( length )`
        ///
        /// More information:
        ///  - [ECMAScript reference][spec]
        ///
        /// [spec]: https://tc39.es/ecma262/#sec-arraybuffer-length
        fn constructor(
            new_target: &JsValue,
            args: &[JsValue],
            context: &mut Context,
        ) -> JsResult<JsValue> {
            if new_target.is_undefined() {
                return Err(
                    JsNativeError::typ()
                        .with_message(
                            "ArrayBuffer.constructor called with undefined new target",
                        )
                        .into(),
                );
            }
            let byte_len = args.get_or_undefined(0).to_index(context)?;
            let max_byte_len = get_max_byte_len(args.get_or_undefined(1), context)?;
            Ok(
                Self::allocate(new_target, byte_len, max_byte_len, context)?
                    .upcast()
                    .into(),
            )
        }
    }
    impl ArrayBuffer {
        /// `ArrayBuffer.isView ( arg )`
        ///
        /// More information:
        ///  - [ECMAScript reference][spec]
        ///
        /// [spec]: https://tc39.es/ecma262/#sec-arraybuffer.isview
        
        fn is_view(
            _: &JsValue,
            args: &[JsValue],
            _context: &mut Context,
        ) -> JsResult<JsValue> {
            Ok(
                args
                    .get_or_undefined(0)
                    .as_object()
                    .is_some_and(|obj| obj.is::<TypedArray>() || obj.is::<DataView>())
                    .into(),
            )
        }
        /// `get ArrayBuffer [ @@species ]`
        ///
        /// More information:
        ///  - [ECMAScript reference][spec]
        ///
        /// [spec]: https://tc39.es/ecma262/#sec-get-arraybuffer-@@species
        
        fn get_species(
            this: &JsValue,
            _: &[JsValue],
            _: &mut Context,
        ) -> JsResult<JsValue> {
            Ok(this.clone())
        }
        /// `get ArrayBuffer.prototype.byteLength`
        ///
        /// More information:
        ///  - [ECMAScript reference][spec]
        ///
        /// [spec]: https://tc39.es/ecma262/#sec-get-arraybuffer.prototype.bytelength
        pub(crate) fn get_byte_length(
            this: &JsValue,
            _args: &[JsValue],
            _: &mut Context,
        ) -> JsResult<JsValue> {
            let buf = this
                .as_object()
                .and_then(JsObject::downcast_ref::<Self>)
                .ok_or_else(|| {
                    JsNativeError::typ()
                        .with_message(
                            "get ArrayBuffer.prototype.byteLength called with invalid `this`",
                        )
                })?;
            Ok(buf.len().into())
        }
        /// [`get ArrayBuffer.prototype.maxByteLength`][spec].
        ///
        /// [spec]: https://tc39.es/ecma262/#sec-get-arraybuffer.prototype.maxbytelength
        pub(crate) fn get_max_byte_length(
            this: &JsValue,
            _args: &[JsValue],
            _context: &mut Context,
        ) -> JsResult<JsValue> {
            let buf = this
                .as_object()
                .and_then(JsObject::downcast_ref::<Self>)
                .ok_or_else(|| {
                    JsNativeError::typ()
                        .with_message(
                            "get ArrayBuffer.prototype.maxByteLength called with invalid `this`",
                        )
                })?;
            let Some(data) = buf.bytes() else {
                return Ok(JsValue::from(0));
            };
            Ok(buf.max_byte_len.unwrap_or(data.len() as u64).into())
        }
        /// [`get ArrayBuffer.prototype.resizable`][spec].
        ///
        /// [spec]: https://tc39.es/ecma262/#sec-get-arraybuffer.prototype.resizable
        pub(crate) fn get_resizable(
            this: &JsValue,
            _args: &[JsValue],
            _context: &mut Context,
        ) -> JsResult<JsValue> {
            let buf = this
                .as_object()
                .and_then(JsObject::downcast_ref::<Self>)
                .ok_or_else(|| {
                    JsNativeError::typ()
                        .with_message(
                            "get ArrayBuffer.prototype.resizable called with invalid `this`",
                        )
                })?;
            Ok(JsValue::from(!buf.is_fixed_len()))
        }
        /// [`ArrayBuffer.prototype.resize ( newLength )`][spec].
        ///
        /// [spec]: https://tc39.es/ecma262/#sec-arraybuffer.prototype.resize
        pub(crate) fn resize(
            this: &JsValue,
            args: &[JsValue],
            context: &mut Context,
        ) -> JsResult<JsValue> {
            let buf = this
                .as_object()
                .and_then(|o| o.clone().downcast::<Self>().ok())
                .ok_or_else(|| {
                    JsNativeError::typ()
                        .with_message(
                            "ArrayBuffer.prototype.resize called with invalid `this`",
                        )
                })?;
            let Some(max_byte_len) = buf.borrow().data.max_byte_len else {
                return Err(
                    JsNativeError::typ()
                        .with_message(
                            "ArrayBuffer.resize: cannot resize a fixed-length buffer",
                        )
                        .into(),
                );
            };
            let new_byte_length = args.get_or_undefined(0).to_index(context)?;
            let mut buf = buf.borrow_mut();
            let Some(buf) = buf.data.vec_mut() else {
                return Err(
                    JsNativeError::typ()
                        .with_message(
                            "ArrayBuffer.resize: cannot resize a detached buffer",
                        )
                        .into(),
                );
            };
            if new_byte_length > max_byte_len {
                return Err(
                    JsNativeError::range()
                        .with_message(
                            "ArrayBuffer.resize: new byte length exceeds buffer's maximum byte length",
                        )
                        .into(),
                );
            }
            buf.resize(new_byte_length as usize, 0);
            Ok(JsValue::undefined())
        }
        /// `ArrayBuffer.prototype.slice ( start, end )`
        ///
        /// More information:
        ///  - [ECMAScript reference][spec]
        ///
        /// [spec]: https://tc39.es/ecma262/#sec-arraybuffer.prototype.slice
        fn slice(
            this: &JsValue,
            args: &[JsValue],
            context: &mut Context,
        ) -> JsResult<JsValue> {
            let buf = this
                .as_object()
                .and_then(|o| o.clone().downcast::<Self>().ok())
                .ok_or_else(|| {
                    JsNativeError::typ()
                        .with_message(
                            "ArrayBuffer.slice called with invalid `this` value",
                        )
                })?;
            let len = {
                let buf = buf.borrow();
                if buf.data.is_detached() {
                    return Err(
                        JsNativeError::typ()
                            .with_message(
                                "ArrayBuffer.slice called with detached buffer",
                            )
                            .into(),
                    );
                }
                buf.data.len() as u64
            };
            let first = Array::get_relative_start(
                context,
                args.get_or_undefined(0),
                len,
            )?;
            let final_ = Array::get_relative_end(
                context,
                args.get_or_undefined(1),
                len,
            )?;
            let new_len = final_.saturating_sub(first);
            let ctor = buf
                .clone()
                .upcast()
                .species_constructor(StandardConstructors::array_buffer, context)?;
            let new = ctor.construct(&[new_len.into()], Some(&ctor), context)?;
            let Ok(new) = new.downcast::<Self>() else {
                return Err(
                    JsNativeError::typ()
                        .with_message("ArrayBuffer constructor returned invalid object")
                        .into(),
                );
            };
            if JsObject::equals(&buf, &new) {
                return Err(
                    JsNativeError::typ()
                        .with_message("new ArrayBuffer is the same as this ArrayBuffer")
                        .into(),
                );
            }
            {
                let mut new = new.borrow_mut();
                let Some(to_buf) = new.data.bytes_mut() else {
                    return Err(
                        JsNativeError::typ()
                            .with_message(
                                "ArrayBuffer constructor returned detached ArrayBuffer",
                            )
                            .into(),
                    );
                };
                if (to_buf.len() as u64) < new_len {
                    return Err(
                        JsNativeError::typ()
                            .with_message("new ArrayBuffer length too small")
                            .into(),
                    );
                }
                let buf = buf.borrow();
                let Some(from_buf) = buf.data.bytes() else {
                    return Err(
                        JsNativeError::typ()
                            .with_message(
                                "ArrayBuffer detached while ArrayBuffer.slice was running",
                            )
                            .into(),
                    );
                };
                let first = first as usize;
                let new_len = new_len as usize;
                to_buf[..new_len].copy_from_slice(&from_buf[first..first + new_len]);
            }
            Ok(new.upcast().into())
        }
        /// `AllocateArrayBuffer ( constructor, byteLength )`
        ///
        /// More information:
        ///  - [ECMAScript reference][spec]
        ///
        /// [spec]: https://tc39.es/ecma262/#sec-allocatearraybuffer
        pub(crate) fn allocate(
            constructor: &JsValue,
            byte_len: u64,
            max_byte_len: Option<u64>,
            context: &mut Context,
        ) -> JsResult<JsObject<ArrayBuffer>> {
            if let Some(max_byte_len) = max_byte_len {
                if byte_len > max_byte_len {
                    return Err(
                        JsNativeError::range()
                            .with_message(
                                "`length` cannot be bigger than `maxByteLength`",
                            )
                            .into(),
                    );
                }
            }
            let prototype = get_prototype_from_constructor(
                constructor,
                StandardConstructors::array_buffer,
                context,
            )?;
            let block = create_byte_data_block(byte_len, max_byte_len, context)?;
            let obj = JsObject::new(
                context.root_shape(),
                prototype,
                Self {
                    data: Some(block),
                    max_byte_len,
                    detach_key: JsValue::Undefined,
                },
            );
            Ok(obj)
        }
    }
    /// Abstract operation [`GetArrayBufferMaxByteLengthOption ( options )`][spec]
    ///
    /// [spec]: https://tc39.es/ecma262/#sec-getarraybuffermaxbytelengthoption
    fn get_max_byte_len(
        options: &JsValue,
        context: &mut Context,
    ) -> JsResult<Option<u64>> {
        let Some(options) = options.as_object() else {
            return Ok(None);
        };
        let max_byte_len = options
            .get(
                {
                    const LITERAL: &crate::string::StaticJsString = &crate::string::StaticJsString::new(
                        ::boa_engine::string::JsStr::latin1(
                            [
                                109,
                                97,
                                120,
                                66,
                                121,
                                116,
                                101,
                                76,
                                101,
                                110,
                                103,
                                116,
                                104,
                            ]
                                .as_slice(),
                        ),
                    );
                    crate::string::JsString::from_static_js_string(LITERAL)
                },
                context,
            )?;
        if max_byte_len.is_undefined() {
            return Ok(None);
        }
        max_byte_len.to_index(context).map(Some)
    }
    /// `CreateByteDataBlock ( size )` abstract operation.
    ///
    /// The abstract operation `CreateByteDataBlock` takes argument `size` (a non-negative
    /// integer). For more information, check the [spec][spec].
    ///
    /// [spec]: https://tc39.es/ecma262/#sec-createbytedatablock
    pub(crate) fn create_byte_data_block(
        size: u64,
        max_buffer_size: Option<u64>,
        context: &mut Context,
    ) -> JsResult<Vec<u8>> {
        let alloc_size = max_buffer_size.unwrap_or(size);
        if !(size <= alloc_size) {
            ::core::panicking::panic("assertion failed: size <= alloc_size")
        }
        if alloc_size > context.host_hooks().max_buffer_size(context) {
            return Err(
                JsNativeError::range()
                    .with_message(
                        "cannot allocate a buffer that exceeds the maximum buffer size",
                    )
                    .into(),
            );
        }
        let alloc_size = alloc_size
            .try_into()
            .map_err(|e| {
                JsNativeError::range()
                    .with_message(
                        ::alloc::__export::must_use({
                            let res = ::alloc::fmt::format(
                                format_args!("couldn\'t allocate the data block: {0}", e),
                            );
                            res
                        }),
                    )
            })?;
        let mut data_block = Vec::new();
        data_block
            .try_reserve_exact(alloc_size)
            .map_err(|e| {
                JsNativeError::range()
                    .with_message(
                        ::alloc::__export::must_use({
                            let res = ::alloc::fmt::format(
                                format_args!("couldn\'t allocate the data block: {0}", e),
                            );
                            res
                        }),
                    )
            })?;
        let size = size as usize;
        data_block.resize(size, 0);
        Ok(data_block)
    }
}
