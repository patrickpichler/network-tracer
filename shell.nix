with import <nixpkgs> {};
stdenv.mkDerivation {
  name = "myenv";
  buildInputs = [ llvmPackages_14.clang-tools llvm_14 clang_14 libbpf ];
}
