{ pkgs }: {
  deps = [
    pkgs.python311
    pkgs.gh
    pkgs.ripgrep
    pkgs.fd
    pkgs.jq
    pkgs.tree
    pkgs.git
    pkgs.postgresql
    pkgs.nodejs_20
    pkgs.curl
    pkgs.wget
    pkgs.htop
    pkgs.tmux
    pkgs.zip
    pkgs.unzip
  ];
}
