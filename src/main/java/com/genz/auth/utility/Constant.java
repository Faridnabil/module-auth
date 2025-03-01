package com.genz.auth.utility;

import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class Constant {
// Private constructor to prevent instantiation

    private Constant() {
        throw new AssertionError("Cannot instantiate Constant class");
    }

    public static final int OK_CODE = 200;
    public static final int INTERNAL_SERVER_ERROR_CODE = 500;
    public static final int NOT_FOUND_CODE = 404;
    public static final int BAD_REQUEST_CODE = 400;
    public static final String SUKSES = "SUKSES";
    public static final String DATA_BERHASIL_DISIMPAN = "Data berhasil disimpan";
    public static final String DATA_DITEMUKAN = "Data ditemukan";
    public static final String DATA_TIDAK_DITEMUKAN = "Data tidak ditemukan";
    public static final String TERJADI_KESALAHAN = "Terjadi kesalahan";
}
