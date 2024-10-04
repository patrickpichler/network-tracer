with import <nixpkgs> {};
stdenv.mkDerivation {
  name = "myenv";
  buildInputs = [ libbpf llvmPackages_14.clang-tools llvm_14 clang_14 ];
}
