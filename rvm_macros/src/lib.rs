use proc_macro::TokenStream;
use syn::{Abi, Attribute, ItemFn};

const ALLOWED_FN_LIST: &[&str] = &[
    "alloc_frame",
    "dealloc_frame",
    "phys_to_virt",
    "is_host_timer_interrupt",
    "is_host_serial_interrupt",
];

#[proc_macro_attribute]
pub fn extern_fn(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attr_str = attr.to_string();
    if !ALLOWED_FN_LIST.contains(&attr_str.as_str()) {
        panic!(
            "Expected one of {:?}, found {:?}",
            ALLOWED_FN_LIST, attr_str
        );
    }

    let mut input = syn::parse_macro_input!(item as ItemFn);
    let attr_name = "rvm_".to_string() + &attr_str;
    let abi: Option<Abi> = syn::parse_quote! {extern "Rust"};
    let attr2: Attribute = syn::parse_quote! { #[export_name = #attr_name] };

    input.sig.abi = abi;
    input.attrs.push(attr2);

    let output = quote::quote! { #input };
    output.into()
}
