#![allow(clippy::collapsible_if)]

use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, LitStr, Type, parse_macro_input};

#[proc_macro_derive(Parser, attributes(arg))]
pub fn derive_parser(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = &input.ident;

    let Data::Struct(data_struct) = input.data else {
        panic!("#[derive(Parser)] is only supported on Structs");
    };

    let Fields::Named(fields) = data_struct.fields else {
        panic!("#[derive(Parser)] requires named fields");
    };

    let mut decls = Vec::new();
    let mut arms = Vec::new();
    let mut help_entries = Vec::new();
    let mut struct_fields = Vec::new();
    let mut subcommand_type = None;

    for field in fields.named {
        let field_name = field.ident.as_ref().unwrap();
        let field_type = &field.ty;

        let mut flag = None;
        let mut short = None;
        let mut help = String::new();
        let mut is_subcommand = false;

        for attr in &field.attrs {
            if attr.path().is_ident("arg") {
                let _ = attr.parse_nested_meta(|meta| {
                    if meta.path.is_ident("flag") {
                        flag = Some(meta.value()?.parse::<LitStr>()?.value());
                    } else if meta.path.is_ident("short") {
                        short = Some(meta.value()?.parse::<LitStr>()?.value());
                    } else if meta.path.is_ident("help") {
                        help = meta.value()?.parse::<LitStr>()?.value();
                    } else if meta.path.is_ident("subcommand") {
                        is_subcommand = true;
                    }
                    Ok(())
                });
            }
        }

        if is_subcommand {
            let sub_ty = option_inner(field_type).expect("#[arg(subcommand)] field must be of type Option<Subcommand>");
            subcommand_type = Some(sub_ty);
            struct_fields.push(quote! { #field_name: sub_cmd });
        } else {
            decls.push(quote! { let mut #field_name = None; });

            let long = flag.unwrap_or_else(|| format!("--{}", field_name.to_string().replace('_', "-")));
            let short_pat = short.as_ref().map(|s| format!("-{s}"));

            let mut pats = vec![quote! { #long }];
            let mut label = format!("{long} <VAL>");
            if let Some(s) = &short_pat {
                pats.push(quote! { #s });
                label = format!("{s}, {long} <VAL>");
            }

            help_entries.push(quote! {
                println!("  {:<28} {}", #label, #help);
            });

            arms.push(quote! {
                #(#pats)|* => {
                    let val = iter.next().ok_or_else(|| format!("Option '{}' requires a value", arg))?;
                    #field_name = Some(val.clone());
                }
            });

            struct_fields.push(quote! { #field_name });
        }
    }

    let sub_cmd_binding = if let Some(sub_ty) = &subcommand_type {
        quote! {
            let (sub_cmd, unhandled) = #sub_ty::parse_subcommand(&unhandled_args)?;
            if !unhandled.is_empty() {
                return Err(format!("Unknown argument: '{}'", unhandled[0]));
            }
        }
    } else {
        quote! {
            let sub_cmd: Option<()> = None;
        }
    };

    let sub_cmd_help = if let Some(sub_ty) = &subcommand_type {
        quote! { #sub_ty::print_help(); }
    } else {
        quote! {}
    };

    let expanded = quote! {
        impl #struct_name {
            pub fn parse() -> Self {
                let args: Vec<String> = std::env::args().skip(1).collect();
                Self::parse_from(&args).unwrap_or_else(|e| {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                })
            }

            pub fn parse_from(args: &[String]) -> Result<Self, String> {
                #(#decls)*

                let mut iter = args.iter();
                let mut unhandled_args: Vec<String> = Vec::new();

                while let Some(arg) = iter.next() {
                    match arg.as_str() {
                        "-h" | "--help" => {
                            Self::print_help();
                            std::process::exit(0);
                        },
                        #(#arms)*
                        _ => unhandled_args.push(arg.clone()),
                    }
                }

                #sub_cmd_binding

                Ok(Self {
                    #(#struct_fields),*
                })
            }

            pub fn print_help() {
                println!("USAGE:\n  ophan [OPTIONS] [COMMAND]\n\nOPTIONS:");
                #(#help_entries)*
                println!("  -h, --help                   Print help information");
                #sub_cmd_help
            }
        }
    };

    TokenStream::from(expanded)
}

#[proc_macro_derive(Subcommand, attributes(arg, cfg))]
pub fn derive_subcommand(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let enum_name = &input.ident;

    let Data::Enum(data_enum) = input.data else {
        panic!("#[derive(Subcommand)] is only supported on Enums");
    };

    let mut arms = Vec::new();
    let mut help_entries = Vec::new();

    for variant in data_enum.variants {
        let var_ident = &variant.ident;
        let mut flag = None;
        let mut short = None;
        let mut help = String::new();
        let mut cfg_attr = None;

        for attr in &variant.attrs {
            if attr.path().is_ident("cfg") {
                cfg_attr = Some(attr.clone());
            } else if attr.path().is_ident("arg") {
                let _ = attr.parse_nested_meta(|meta| {
                    if meta.path.is_ident("flag") {
                        flag = Some(meta.value()?.parse::<LitStr>()?.value());
                    } else if meta.path.is_ident("short") {
                        short = Some(meta.value()?.parse::<LitStr>()?.value());
                    } else if meta.path.is_ident("help") {
                        help = meta.value()?.parse::<LitStr>()?.value();
                    }
                    Ok(())
                });
            }
        }

        let long = flag.unwrap_or_else(|| format!("--{}", var_ident.to_string().to_lowercase()));
        let short_pat = short.as_ref().map(|s| format!("-{s}"));

        let mut pats = vec![quote! { #long }];
        let mut label = long.clone();
        if let Some(s) = &short_pat {
            pats.push(quote! { #s });
            label = format!("{s}, {long}");
        }

        help_entries.push(quote! {
            #cfg_attr
            println!("  {:<28} {}", #label, #help);
        });

        let is_tuple = matches!(variant.fields, Fields::Unnamed(_));

        let arm = if is_tuple {
            quote! {
                #cfg_attr
                #(#pats)|* => {
                    let val = iter.next().ok_or_else(|| format!("Command '{}' requires a value", arg))?;
                    let parsed_val = val.parse().map_err(|_| format!("Invalid value for '{}'", arg))?;
                    return Ok((Some(#enum_name::#var_ident(parsed_val)), iter.cloned().collect()));
                }
            }
        } else {
            quote! {
                #cfg_attr
                #(#pats)|* => {
                    return Ok((Some(#enum_name::#var_ident), iter.cloned().collect()));
                }
            }
        };

        arms.push(arm);
    }

    let expanded = quote! {
        impl #enum_name {
            pub fn parse_subcommand(args: &[String]) -> Result<(Option<Self>, Vec<String>), String> {
                let mut iter = args.iter();
                while let Some(arg) = iter.next() {
                    match arg.as_str() {
                        #(#arms)*
                        _ => return Ok((None, args.to_vec())),
                    };
                }
                Ok((None, Vec::new()))
            }

            pub fn print_help() {
                println!("\nCOMMANDS:");
                #(#help_entries)*
            }
        }
    };

    TokenStream::from(expanded)
}

fn option_inner(ty: &Type) -> Option<Type> {
    if let Type::Path(tp) = ty {
        if let Some(seg) = tp.path.segments.last() {
            if seg.ident == "Option" {
                if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                    if let Some(syn::GenericArgument::Type(inner)) = args.args.first() {
                        return Some(inner.clone());
                    }
                }
            }
        }
    }
    None
}
