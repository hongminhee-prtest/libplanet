workflow "Build docs" {
  on = "push"
  resolves = ["DocFX"]
}

action "DocFX" {
  uses = "docker://tsgkadot/docker-docfx"
  args = "docfx Docs/docfx.json"
}
