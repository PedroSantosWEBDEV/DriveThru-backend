<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\ProductController;

Route::group([
    'middleware' => 'api',
    'prefix' => 'auth'
], function ($router) {
    Route::post('/login', [AuthController::class, 'login']);
    Route::post('/register', [AuthController::class, 'register']);
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::post('logoutall', [App\Http\Controllers\AuthController::class, 'logoutall']);
    Route::post('/verify_token', [AuthController::class, 'verify_token']);  
    Route::post('me', [App\Http\Controllers\AuthController::class, 'me']); 
    Route::post('token/issue', [App\Http\Controllers\AuthController::class, 'tokenIssue']);
});

Route::controller(ProductController::class)->group(function () {
    Route::get('products', 'index');
    Route::post('product', 'store');
    Route::get('product/{id}', 'show');
    Route::put('product/{id}', 'update');
    Route::delete('product/{id}', 'destroy');
}); 

Route::any('{any}', function(){
    return response()->json([
    	'status' => 'error',
        'message' => 'Resource not found'], 404);
})->where('any', '.*');