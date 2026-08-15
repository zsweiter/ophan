function readPackage(pkg) {
    if (["esbuild", "sharp"].includes(pkg.name)) {
        pkg.allowBuild = true;
    }
    
    return pkg;
}

module.exports = {
    hooks: {
        readPackage,
    },
};
