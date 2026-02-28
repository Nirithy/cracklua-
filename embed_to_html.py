import os
import re

def embed_wasm_js(template_path, js_path, output_path):
    print(f"[*] Reading template: {template_path}")
    with open(template_path, "r", encoding="utf-8") as f:
        template = f.read()

    print(f"[*] Reading JS/WASM: {js_path}")
    with open(js_path, "r", encoding="utf-8") as f:
        js_content = f.read()

    # Create script tag with JS content
    script_tag = f"<script type=\"text/javascript\">\n{js_content}\n</script>"

    # Replace placeholder
    final_html = template.replace("<!-- WASM_JS_PLACEHOLDER -->", script_tag)

    print(f"[*] Writing final HTML: {output_path}")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(final_html)

    print(f"[+] Success! Final HTML size: {len(final_html)} bytes")

if __name__ == "__main__":
    template_file = "template.html"
    js_file = "decryptors.js"
    output_file = "index.html"

    if os.path.exists(template_file) and os.path.exists(js_file):
        embed_wasm_js(template_file, js_file, output_file)
    else:
        print("Error: template.html or decryptors.js not found.")
