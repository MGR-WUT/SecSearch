import subprocess
import json
import tempfile


def run_bandit(code: str) -> dict[list[dict]]:
    with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as f:
        f.write(code.encode())
        path = f.name

    result = subprocess.run(
        ["bandit", "-f", "json", path], capture_output=True, text=True
    )

    return json.loads(result.stdout)


if __name__ == "__main__":
    code = """
import os
import shutil
import urllib.request
from urllib.parse import urlparse


def process_product_packages(products, build_folder):
    os.makedirs(build_folder, exist_ok=True)

    for product, packages in products.items():
        staging_folder = os.path.join(build_folder, product, "staging")
        final_folder = os.path.join(build_folder, product, "final")

        os.makedirs(staging_folder, exist_ok=True)
        os.makedirs(final_folder, exist_ok=True)

        for i, package_url in enumerate(packages):
            filename = (
                os.path.basename(urlparse(package_url).path)
                or f"package_{i}.archive"
            )

            download_path = os.path.join(staging_folder, filename)

            urllib.request.urlretrieve(package_url, download_path)

            extract_path = os.path.join(staging_folder, f"extracted_{i}")
            os.makedirs(extract_path, exist_ok=True)

            shutil.unpack_archive(download_path, extract_path)

            for root, _, files in os.walk(extract_path):
                for file in files:
                    src_path = os.path.join(root, file)

                    rel_dir = os.path.relpath(root, extract_path)
                    dst_dir = os.path.join(final_folder, rel_dir)
                    dst_path = os.path.join(dst_dir, file)

                    os.makedirs(dst_dir, exist_ok=True)
                    shutil.move(src_path, dst_path)

        zip_base_name = os.path.join(
            build_folder,
            product,
            f"{product}_final",
        )

        shutil.make_archive(zip_base_name, "zip", final_folder)

"""
    results = run_bandit(code)
    print(results)
