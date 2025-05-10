<?php

namespace Database\Seeders;

use App\Models\User;
use App\Models\Post;
use App\Models\Comment;
// use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;

class DatabaseSeeder extends Seeder
{
    public function run(): void
    {
        // Create test user
        $testUser = User::factory()->create([
            'username' => 'Test User',
            'email' => 'test@example.com',
        ]);

        // Create 4 more users
        $otherUsers = User::factory(4)->create();

        // Merge all users
        $users = $otherUsers->prepend($testUser);

        // Create 10 posts
        $posts = Post::factory(10)->create();

        // Each user comments once on each post
        foreach ($users as $user) {
            foreach ($posts as $post) {
                Comment::factory()->create([
                    'user_id' => $user->id,
                    'post_id' => $post->id,
                ]);
            }
        }
    }
}
