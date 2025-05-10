<x-layout>
    <x-slot:title>User Page</x-slot:title>

    <div style="font-family: Arial, sans-serif; padding: 40px; max-width: 1200px; margin: auto;">

        <div style="display: flex; gap: 30px; align-items: flex-start;">

            <!-- Profile Container -->
            <div style="flex: 1; padding: 20px; border: 1px solid #ccc; border-radius: 8px; background-color: #f2f2f2;">
                <h2 style="margin-top: 0;">Profile</h2>
                <div style="display: flex; justify-content: center; margin-bottom: 20px;">

                    <input type="file" id="profile_picture" name="profile_picture" accept="image/*" style="display: none;">
                </div>
                <form method="post" action="/users/{{$user->id}}">
                    @csrf
                    @method('patch')
                    <div style="margin-bottom: 15px;">
                        <label for="username" style="display: block; margin-bottom: 5px;">Username:</label>
                        <input value="{{ $user->username }}" type="text" id="username" name="username" required
                            style="width: 100%; padding: 8px; border: 1px solid #aaa; border-radius: 4px;">
                    </div>

                    <div style="margin-bottom: 15px;">
                        <label for="email" style="display: block; margin-bottom: 5px;">Email:</label>
                        <input value="{{ $user->email }}" type="text" id="email" name="email" required
                            style="width: 100%; padding: 8px; border: 1px solid #aaa; border-radius: 4px;">
                    </div>

                    <div style="margin-bottom: 15px;">
                        <label for="password" style="display: block; margin-bottom: 5px;">Password:</label>
                        <input value="{{ $user->password }}" type="text" id="password" name="password" required
                            style="width: 100%; padding: 8px; border: 1px solid #aaa; border-radius: 4px;">
                    </div>

                    @auth
                    <button type="submit"
                        style="padding: 10px 15px; background-color: #333; color: white; border: none; border-radius: 4px; cursor: pointer;">
                        Save Changes
                    </button>
                    <button form="delete-form" type="submit"
                        style="padding: 10px 15px; background-color:rgb(180, 35, 35); color: white; border: none; border-radius: 4px; cursor: pointer;">
                        Delete Account
                    </button>
                    @endauth
                </form>

                <form method="post" action="/users/{{$user->id}}" id="delete-form" class="hidden">
                    @csrf
                    @method('DELETE')
                </form>

            </div>

            <!-- Blog Container -->
            <div style=" flex: 2; padding: 20px; border: 1px solid #ccc; border-radius: 8px; font-size: 20px; background-color: #fff; max-height: 600px; overflow-y: auto; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI' , Roboto, Helvetica, Arial, sans-serif;">
                <h2 style="margin-top: 0;">Blog Posts</h2>

                @foreach($user->posts as $post)
                @php
                $preview = Str::limit($post->content, 300, '...');
                @endphp
                <div style=" margin-bottom: 30px; border-bottom: 1px solid #eee; padding-bottom: 15px;">
                    <h3 style="margin-bottom: 10px; font-size: 1.25rem; font-weight: 600;">
                        {{ $post->title }} <span style="font-weight: normal; color: #666;">Author: {{ $post->user->username ?? 'Unknown' }}</span>
                    </h3>
                    <p style="margin: 0;">{{ $preview }}</p>
                    <div style="margin-top: 10px; display: flex; gap: 10px;">
                        <button onclick="openModal({{ $post->id }})" style="padding: 6px 10px;">Read More</button>

                        <button style="padding: 6px 10px; background-color: #dc3545; color: #fff; border: none; border-radius: 4px;">
                            Edit
                        </button>

                        <button style="padding: 6px 10px; background-color: #dc3545; color: #fff; border: none; border-radius: 4px;">
                            Delete
                        </button>

                    </div>
                </div>

                <div id="modal-{{ $post->id }}" style="
                        display: none;
                        position: fixed;
                        top: 10%;
                        left: 50%;
                        transform: translateX(-50%);
                        width: 80%;
                        max-width: 800px;
                        max-height: 80vh;
                        overflow-y: auto;
                        background: #fff;
                        padding: 20px;
                        border: 1px solid #ccc;
                        border-radius: 6px;
                        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                        z-index: 1000;
                    ">
                    <div style="overflow: hidden;">
                        <img src="/image/download.jpg" alt="img"
                            style="width: 130px; height: 130px; object-fit: cover; border-radius: 4px; float: left; margin: 0 15px 10px 0;">

                        <h3 style="margin-top: 0;">{{ $post->title ?? 'Post' }}</h3>
                        <p style="text-align: justify;">{{ $post->content }}</p>
                        <p style="font-size: 0.9em; color: #555;">
                            Author: {{ $post->user->username ?? 'Unknown' }}
                        </p>
                        <p style="font-size: 0.8em; color: #888;">
                            Posted at: {{ $post->created_at->format('M d, Y H:i') }}
                        </p>
                    </div>


                    <!-- Comment Button -->
                    <div style="margin-top: 20px;">
                        <button type="button" onclick="toggleCommentForm({{ $post->id }})"
                            style="padding: 6px 12px; background-color: #007BFF; color: #fff; border: none; border-radius: 4px; cursor: pointer;">
                            Comment
                        </button>
                    </div>
                    <!-- Hidden Comment Form -->
                    <div id="comment-form-{{ $post->id }}" style="display: none; margin-top: 10px;">
                        <form method="POST" action="/comment">
                            @csrf
                            <input type="hidden" name="post_id" value="{{ $post->id }}">

                            <textarea name="content" rows="3" placeholder="Write your comment..." required
                                style="width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 6px; resize: vertical;"></textarea>

                            <div style="margin-top: 10px; display: flex; gap: 10px;">
                                <button type="submit"
                                    style="padding: 6px 12px; background-color: #28a745; color: #fff; border: none; border-radius: 4px; cursor: pointer;">
                                    Post Comment
                                </button>

                                <button type="button" onclick="toggleCommentForm({{ $post->id }})"
                                    style="padding: 6px 12px; background-color: #dc3545; color: #fff; border: none; border-radius: 4px; cursor: pointer;">
                                    Cancel
                                </button>
                            </div>
                        </form>
                    </div>
                    <!-- Comments Section -->

                    <div style="margin-top: 20px;">
                        <h4 style="margin-bottom: 10px;">Comments</h4>
                        @foreach ($post->comments as $comment)
                        <div style="margin-bottom: 12px; border-bottom: 1px solid #eee; padding-bottom: 8px;">
                            <strong>{{ $comment->user->username ?? 'Deleted User' }}</strong>

                            <p>{{ $comment->content }}</p>
                        </div>
                        @endforeach

                    </div>
                    <div style="text-align: right; margin-top: 10px;">
                        <button onclick="closeModal({{ $post->id }})" style="padding: 5px 10px;">Close</button>
                    </div>



                </div>
                @endforeach


            </div>
        </div>
    </div>

    <script>
        function toggleCommentForm(postId) {
            const form = document.getElementById(`comment-form-${postId}`);
            form.style.display = form.style.display === 'none' ? 'block' : 'none';
        }

        function openCreatePost() {
            document.getElementById('create_post').style.display = 'block';
        }

        // Function to close the modal
        function closeCreatePost() {
            document.getElementById('create_post').style.display = 'none';
        }

        // Function to handle the post creation (this is just an example function for now)
        function createPost() {
            // Handle post creation logic here
            closeCreatePost(); // Optionally close the modal after post creation
        }


        function openModal(id) {
            document.getElementById('modal-' + id).style.display = 'block';
        }

        function closeModal(id) {
            document.getElementById('modal-' + id).style.display = 'none';
        }
    </script>
</x-layout>