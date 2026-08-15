// @ts-check
import { defineConfig } from "astro/config";
import mdx from "@astrojs/mdx";
import tailwindcss from "@tailwindcss/vite";
import remarkGfm from "remark-gfm";
import theme from "./shiki.theme.json" with { type: "json" };

export default defineConfig({
    site: "https://zsweiter.github.io/ophan",
    integrations: [mdx()],
    vite: {
        plugins: [tailwindcss()],
        server: {
            port: 8050,
            strictPort: true,
            allowedHosts: ["ophan.me", "ophan.dev"],
            hmr: {
                protocol: "ws",
                host: "localhost",
                port: 8050,
                path: "vite",
            },
        },
    },
    server: {
        port: 8050,
    },
    devToolbar: {
        enabled: false,
    },
    markdown: {
        shikiConfig: {
            // @ts-ignore
            theme: theme,
        },
        remarkPlugins: [remarkGfm],
    },
});
