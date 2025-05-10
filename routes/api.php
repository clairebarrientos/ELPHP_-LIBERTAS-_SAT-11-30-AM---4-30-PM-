<?php

use App\Http\Requests\UpdatePostRequest;
use Illuminate\Support\Facades\Route;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

use App\Models\User;
use App\Models\Post;
use App\Models\Comment;


Route::POST('/login', function (Request $request) {
    $request->validate([
        'email' => 'required|email',
        'password' => 'required'
    ]);

    $user = User::where('email', $request->email)->first();


    if (!$user || !Hash::check($request->password, $user->password)) {
        return response()->json(['message' => 'Invalid credentials'], 401);
    }

    $user->tokens()->delete();

    $token = $user->createToken('postman')->plainTextToken;

    return response()->json([
        'message' => 'Logged in',
        'token' => $token,
        'Welcome' => $user->username
    ]);
});

Route::POST('/register', function (Request $request) {
    $request->validate([
        'username' => 'required|string|max:255|unique:users,username',
        'email'    => 'required|email|unique:users,email',
        'password' => 'required|string|min:6',
    ]);

    $user = User::create([
        'username' => $request->username,
        'email'    => $request->email,
        'password' => $request->password,
    ]);

    return response()->json([
        'message' => 'Registered successfully please login',
        'username'    => $user->username,
        'email' => $user->email
    ]);
});


# posts (Public)
Route::GET('/posts', function () {
    $post = Post::with('user.comments')->get();

    $posts = $post->map(function ($post) {
        return [
            "post_id" => $post->id,
            "title" => $post->title,
            "content" => $post->content,
            "author" => $post->user->username,
            "created_at" => $post->created_at,
            "comments" => $post->comments->map(function ($comment) {
                return [
                    "comment_id" => $comment->id,
                    "commentor" => $comment->user->username,
                    "comment" => $comment->content
                ];
            })
        ];
    });

    return response()->json(["Feed" => $posts]);
});

Route::GET('/posts/recent', function () {
    $post = Post::with(['user.comments.user'])->latest()->get();
    $posts = $post->map(function ($post) {
        return [
            "post_id" => $post->id,
            "title" => $post->title,
            "content" => $post->content,
            "author" => $post->user->username,
            "created_at" => $post->created_at,
            "comments" => $post->comments->map(function ($comment) {
                return [
                    "comment_id" => $comment->id,
                    "commentor" => $comment->user->username,
                    "comment" => $comment->content
                ];
            })
        ];
    });

    return response()->json(["recent feed" => $posts]);
});
Route::GET('/posts/title/{title}', function ($title) {
    $post = Post::with(['user.comments.user'])
        ->where('title', 'LIKE', "%{$title}%")->get();

    $posts = $post->map(function ($post) {
        return [
            "post_id" => $post->id,
            "title" => $post->title,
            "content" => $post->content,
            "author" => $post->user->username,
            "created_at" => $post->created_at->toDateTimeString(),
            "comments" => $post->comments->map(function ($comment) {
                return [
                    "comment_id" => $comment->id,
                    "commentor" => $comment->user->username,
                    "comment" => $comment->content

                ];
            })
        ];
    });
    return response()->json(["Search results" => $posts]);
});

Route::GET('/posts/username/{username}', function ($username) {
    $user = User::with('posts.comments')->where('username', $username)->first();
    if (!$user) {
        return response()->json('Author not found');
    }
    $posts = $user->posts->map(function ($post) {
        return [
            "post_id" => $post->id,
            "title" => $post->title,
            "content" => $post->content,
            "created_at" => $post->created_at,
            "comments" => $post->comments->map(function ($comment) {
                return [
                    "comment_id" => $comment->id,
                    "commentor" => $comment->user->username,
                    "content" => $comment->content

                ];
            })
        ];
    });
    return response()->json([
        "Author" =>  $user->username,
        "Posts" => $posts
    ]);
});

Route::GET('/posts/{id}', function ($id) {
    $post = Post::with(['user.comments'])->find($id);

    if (!$post) {
        return response()->json(["message" => "post not found"]);
    }

    $posts = [
        "post_id" => $post->id,
        "title" => $post->title,
        "content" => $post->content,
        "author" => $post->user->username,
        "created_at" => $post->created_at->toDateTimeString(),
        "comments" => $post->comments->map(function ($comment) {
            return [
                "comment_id" => $comment->id,
                "commentor" => $comment->user->username,
                "comment" => $comment->content
            ];
        })
    ];

    return response()->json($posts);
});




# Authentication
Route::middleware(['auth:sanctum'])->group(function () {
    Route::GET('/status', function (Request $request) {
        return response()->json([
            'message' => 'You are authenticated',
            'user' => $request->user()
        ]);
    });
    Route::POST('/logout', function (Request $request) {
        $request->user()->currentAccessToken()->delete();
        return response()->json(['message' => 'Logged out']);
    });

    Route::GET('/users', function () {
        $users = User::all();

        $all = $users->map(function ($user) {
            return [
                "username" => $user->username,
                "created_at" => $user->created_at
            ];
        });

        return response()->json(
            [
                "registered users" => $all
            ]
        );
    });
    Route::GET('/users/{username}', function ($username) {
        $user = User::where('username', $username)->first();

        if (!$user) {
            return response()->json(['message' => 'User not found']);
        }

        $user = [
            "username" => $user->username,
            "created_at" => $user->created_at
        ];


        return response()->json(
            ["registered user" => $user]
        );
    });

    Route::GET('/me', function () {
        $user = User::with('posts.comments.user')->find(auth()->id());
        $personal_info = [
            "username" => $user->username,
            "email" => $user->email,
            "created_at" => $user->created_at
        ];
        $posts = $user->posts->map(function ($post) {
            return [
                "post_id" => $post->id,
                'post_id' => $post->id,
                'title' => $post->title,
                'content' => $post->content,
                'created_at' => $post->created_at,
                'comments' => $post->comments->map(function ($comment) {
                    return [
                        "comment_id" => $comment->id,
                        'commentor' => $comment->user->username,
                        'content' => $comment->content,
                    ];
                }),
            ];
        });
        return response()->json(
            [
                "profile" => $personal_info,
                "My Post" => $posts
            ]
        );
    });
    Route::PATCH('/me', function (Request $request) {
        $request->validate([
            'username' => 'required',
            'email'    => 'required'
        ]);

        $user = User::findOrFail(auth()->id());

        $user->update([
            'username' => $request->input('username'),
            'email'    => $request->input('email'),
        ]);

        return response()->json([
            'message' => 'Account updated successfully',
            'user'    => $user
        ]);
    });

    Route::PATCH('/me/password', function (Request $request) {
        $request->validate([
            'current_password' => 'required|string',
            'new_password' => 'required|string|min:6|confirmed'
        ]);

        $user = auth()->user();

        if (!$user || !Hash::check($request->current_password, $user->password)) {
            return response()->json(['message' => 'Current password is incorrect']);
        }

        $user->update([
            'password' => Hash::make($request->new_password)
        ]);

        return response()->json(['message' => 'Password updated successfully']);
    });

    Route::DELETE('/me', function (Request $request) {
        $request->validate([
            'current_password' => 'required|string',
        ]);

        $user = auth()->user();
        if (!$user || !Hash::check($request->current_password, $user->password)) {
            return response()->json(['message' => 'Password is incorrect']);
        }

        $user = User::findorfail(auth()->id());
        $user->delete();
        $user->tokens()->delete();
        return response()->json(['message' => 'User deleted successfully']);
    });

    Route::POST('/posts', function (Request $request) {
        $request->validate([
            'title'   => ['required'],
            'content' => ['required'],
        ]);

        $attributes = [
            "user_id" => auth()->id(),
            'title' => $request->title,
            'content' => $request->content
        ];

        $post = Post::create($attributes);
        $post = [
            'title' => $post->title,
            'content' => $post->content
        ];

        return response()->json([
            'message' => 'Post created successfully',
            'post'    => $post
        ]);
    });
    Route::PATCH('/posts/{id}', function (Request $request, $id) {

        $rules = [];
        if ($request->has('title')) {
            $rules['title'] = 'required|string';
        }
        if ($request->has('content')) {
            $rules['content'] = 'required|string';
        }

        if (empty($rules)) {
            return response()->json(['message' => 'At least one of title or content is required']);
        }

        $validated = $request->validate($rules);

        $post = Post::find($id);
        if (!$post) {
            return response()->json(['message' => 'Post not found']);
        }

        if ($post->user_id !== auth()->id()) {
            return response()->json(['message' => 'Unauthorized']);
        }

        $post->update($validated);

        $post = [
            "post_id" => $post->id,
            "title" => $post->title,
            "content" => $post->content,
            "created_at" => $post->created_at,
            "updated_at" => $post->updated_at
        ];

        return response()->json([
            'message' => 'Post updated successfully',
            'updated' => $post
        ]);
    }); // Update post

    Route::DELETE('/posts/{id}', function ($id) {
        $post = Post::find($id);
        if (!$post) {
            return response()->json(['message' => 'post  not found'], 404);
        }
        if ($post->user_id !== auth()->id()) {
            return response()->json(['message' => 'Unauthorized'], 403);
        }

        $post->delete();

        return response()->json(['message' => 'Post deleted successfully']);
    });

    Route::POST('/posts/{post_id}/comments', function (Request $request, $post_id) {
        $request->validate([
            'content' => 'required'
        ]);

        $post = Post::find($post_id);
        if (!$post) {
            return response()->json(['message' => 'Post not found']);
        }

        $attributes = [
            'user_id' => auth()->id(),
            'post_id' => $post_id,
            'content' => $request->content


        ];
        $comment = Comment::create($attributes);
        $comment = [
            "title" => $post->title,
            "comment" => $comment->content
        ];

        return response()->json([
            'message' => 'Comment created successfully',
            'created_comment' => $comment
        ]);
    }); // Create comment under a specific post
    Route::PATCH('/comments/{id}', function (Request $request, $id) {
        $request->validate([
            'post_id'  => 'required|integer',
            'content'  => 'required|string'
        ]);
        $comment = Comment::with('post')->find($id);

        if (!$comment) {
            return response()->json(['message' => 'Comment not found']);
        }

        if (!$comment->post || $comment->post->id !== $request->post_id) {
            return response()->json(['message' => 'Comment does not belong to this post']);
        }

        if ($comment->user_id !== auth()->id()) {
            return response()->json(['message' => 'Unauthorized']);
        }

        $old_comment = $comment->content;

        $comment->update([
            'content' => $request->content,
        ]);

        $comment = [
            'title' => $comment->post->title,
            'old_comment' => $old_comment,
            'updated_comment' => $comment->content
        ];


        return response()->json([
            'message' => 'Comment updated successfully',
            'updated_comment' => $comment
        ]);
    });
    Route::DELETE('/comments/{id}', function ($id) {
        $comment = Comment::find($id);
        if (!$comment) {
            return response()->json(['message' => 'Comment  not found']);
        }

        if ($comment->user_id !== auth()->id()) {
            return response()->json(['message' => 'Unauthorized']);
        }

        $comment->delete();

        return response()->json([
            'message' => 'Comment deleted successfully',
            'comment_id' => $comment->id
        ]);
    });
});
