package com.genz.auth.common;

import io.quarkus.runtime.annotations.RegisterForReflection;

@RegisterForReflection
public class ApiResponse<T> {

    private static final int OK_CODE = 200;
    private static final int ERROR_CODE = 500;
    private static final int NOT_FOUND_CODE = 404;
    private static final int BAD_REQUEST_CODE = 400;
    private static final String MESSAGE_SUCCESS = "success";

    private int status;
    private boolean success;
    private String message;
    private T data;

    // Default Constructor
    public ApiResponse() {
    }

    public ApiResponse(int status, boolean success, String message, T data) {
        this.status = status;
        this.success = success;
        this.message = message;
        this.data = data;
    }

    // Static factory methods
    public static <T> ApiResponse<T> ok(T data) {
        return new ApiResponse<>(OK_CODE, true, MESSAGE_SUCCESS, data);
    }

    public static <T> ApiResponse<T> ok(T data, String message) {
        return new ApiResponse<>(OK_CODE, true, message, data);
    }

    public static <T> ApiResponse<T> error(String message) {
        return new ApiResponse<>(ERROR_CODE, false, message, null);
    }

    public static <T> ApiResponse<T> notFound(String message) {
        return new ApiResponse<>(NOT_FOUND_CODE, false, message, null);
    }

    public static <T> ApiResponse<T> badRequest(String message) {
        return new ApiResponse<>(BAD_REQUEST_CODE, false, message, null);
    }

    // Getters and Setters
    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public T getData() {
        return data;
    }

    public void setData(T data) {
        this.data = data;
    }

    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }
}
