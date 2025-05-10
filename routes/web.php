<?php


use App\Http\Controllers\CommentController;
use App\Http\Controllers\PostController;
use App\Http\Controllers\RegisteredUserController;
use App\Http\Controllers\UserController;
use App\Http\Controllers\SessionController;
use Illuminate\Support\Facades\Route;
use App\Models\Post;
use Illuminate\Auth\Events\Registered;

// homepage

Route::get('/', function () {

    $posts = Post::with(['user', 'comments.user'])->get();

    return view('homepage.index', ['posts' => $posts]);
});



Route::controller(UserController::class)->group(function () {
    Route::get('/users', 'index');


    Route::get('/users/{id}', 'account');


    Route::patch('/users/{user}',  'update');

    Route::delete('/users/{user}',  'delete');
});


Route::controller(RegisteredUserController::class)->group(function () {

    Route::get('/register', 'create');
    Route::post('/register', 'store');
});
Route::controller(SessionController::class)->group(function () {
    Route::get('/login', 'create');
    Route::post('/login', 'store');
    Route::post('/logout', 'destroy');
});


Route::controller(PostController::class)->group(function () {
    Route::post('/post', 'store');
    Route::delete('/post/{post}', 'destroy');
});
Route::controller(CommentController::class)->group(function () {
    Route::post('/comment', 'store');
    Route::delete('/comment/{comment}', 'destroy');
});
# for reference soon
# Route::get('/users', [UserController::class, 'index']);
# Route::patch('/users/account/{user}', [UserController::class, 'update']);

# Route::delete('/users/account/{user}', [UserController::class, 'delete']);
