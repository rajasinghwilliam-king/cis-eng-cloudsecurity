# Package the app: zip everything under package_source_dir (../src by default, or a build
# output for compiled runtimes) into a single deployment artifact. Terraform performs the zip,
# and the function_app module deploys it via run-from-package.
data "archive_file" "package" {
  count = var.deploy_package ? 1 : 0

  type        = "zip"
  source_dir  = var.package_source_dir
  output_path = "${path.module}/.builds/${local.function_app_name}.zip"
}
