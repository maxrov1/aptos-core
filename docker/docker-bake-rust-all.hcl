# This is a docker bake file in HCL syntax.
# It provides a high-level mechenanism to build multiple dockerfiles in one shot.
# Check https://crazymax.dev/docker-allhands2-buildx-bake and https://docs.docker.com/engine/reference/commandline/buildx_bake/#file-definition for an intro.


variable "BUILD_DATE" {}
variable "GIT_REV" {}
variable "AWS_REGION" {}
variable "AWS_ACCESS_KEY_ID" {}
variable "AWS_SECRET_ACCESS_KEY" {}

variable "ecr_base" {
  default = "ghcr.io/aptos-labs/aptos-core"
  // default = "323143817725.dkr.ecr.us-west-2.amazonaws.com/aptos-labs/aptos-core"
}
variable "gh_image_cache" {
  default = "ghcr.io/aptos-labs/aptos-core/image-cache"
}

group "all" {
  targets = [
    "validator",
    // "indexer",
    // "safety-rules",
    // "tools",
    // "init",
    // "transaction-emitter",
    // "faucet",
    // "forge",
  ]
}

target "_common" {
  dockerfile = "docker/rust-all.Dockerfile"
  context    = "."
  // cache-from = ["type=registry,ref=${gh_image_cache}"]
  cache-to   = ["type=registry,ref=${gh_image_cache},mode=max"]
  labels = {
    "org.label-schema.schema-version" = "1.0",
    "org.label-schema.build-date"     = "${BUILD_DATE}"
    "org.label-schema.vcs-ref"        = "${GIT_REV}"
  }
  args = {
    IMAGE_TARGETS         = "release"
    AWS_REGION            = "${AWS_REGION}"
    AWS_ACCESS_KEY_ID     = "${AWS_ACCESS_KEY_ID}"
    AWS_SECRET_ACCESS_KEY = "${AWS_SECRET_ACCESS_KEY}"
  }
}

target "validator" {
  inherits = ["_common"]
  target   = "validator"
  tags     = generate_tags("validator")
}

target "indexer" {
  inherits = ["_common"]
  target   = "indexer"
  tags     = generate_tags("indexer")
}

target "safety-rules" {
  inherits = ["_common"]
  target   = "safety-rules"
  tags     = generate_tags("safety-rules")
}

target "tools" {
  inherits = ["_common"]
  target   = "tools"
  tags     = generate_tags("tools")
}

target "init" {
  inherits = ["_common"]
  target   = "init"
  tags     = generate_tags("init")
}

target "transaction-emitter" {
  inherits = ["_common"]
  target   = "transaction-emitter"
  tags     = generate_tags("transaction-emitter")
}

target "faucet" {
  inherits = ["_common"]
  target   = "faucet"
  tags     = generate_tags("faucet")
  args = {
    IMAGE_TARGETS = "test"
  }
}

target "forge" {
  inherits = ["_common"]
  target   = "forge"
  tags     = generate_tags("forge")
  args = {
    IMAGE_TARGETS = "test"
  }
}



function "generate_tags" {
  params = [target]
  result = ["${ecr_base}/${target}:dev_${GIT_REV}"]
}