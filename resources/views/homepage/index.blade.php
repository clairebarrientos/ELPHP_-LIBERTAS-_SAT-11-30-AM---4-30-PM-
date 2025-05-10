<x-layout>
    <x-slot:title>Home Page </x-slot:title>
    <div style="display: flex; gap: 10px;">
        <div style="flex: 1; height: 150px;">

            <h2>
                Welcome {{ auth()->user()?->username ?? 'Guest' }}</h2>


        </div>
        <div style="flex: 4; height: 150px; ">
            <div style="flex: 2; height: 600px; border: 2px solid beige; overflow: auto; padding: 10px;">

                <div id="create_post" style="
                            display: none;
                            position: fixed;
                            top: 10%;
                            left: 50%;
                            transform: translateX(-50%);
                            width: 80%;
                            max-width: 800px;
                            max-height: 80vh;
                            background: #fff;
                            padding: 20px;
                            border: 1px solid #ccc;
                            border-radius: 6px;
                            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                            z-index: 1000;
                    ">
                    <form method="POST" action="/post">
                        @csrf
                        <h3 style="margin-bottom: 15px; font-weight: bold;">Create a New Blog</h3>

                        <div style="margin-bottom: 15px;">
                            <label for="title" style="display: block; margin-bottom: 5px; font-weight: 500;">Title</label>
                            <textarea name="title" rows="2" placeholder="Enter your title..."
                                style="width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 6px; resize: vertical;"></textarea>
                            @error('title')
                            <div style="color: red; margin-top: 5px;">{{ $message }}
                            </div>
                            @enderror
                        </div>

                        <div style="margin-bottom: 15px;">
                            <label for="content" style="display: block; margin-bottom: 5px; font-weight: 500;">Content</label>
                            <textarea name="content" rows="6" placeholder="Write your post content here..."
                                style="width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 6px; resize: vertical;"></textarea>
                            @error('content')
                            <div style="color: red; margin-top: 5px;">{{ $message }}</div>
                            @enderror
                        </div>



                        <div style="display: flex; gap: 10px;">
                            <button type="dd(request->usernam);"
                                style="padding: 10px 16px; background-color: #007BFF; color: white; border: none; border-radius: 5px; cursor: pointer;">
                                Post
                            </button>

                            <button type="button" onclick="closeCreatePost()"
                                style="padding: 10px 16px; background-color: #6c757d; color: white; border: none; border-radius: 5px; cursor: pointer;">
                                Cancel
                            </button>
                        </div>
                    </form>
                </div>

                @auth
                <!-- Clickable Text to Open Modal -->
                <div style="margin-bottom: 30px; border-bottom: 1px solid #eee; padding-bottom: 15px; cursor: pointer; display: flex; justify-content: center; align-items: center;" onclick="openCreatePost()">
                    <h3 style="margin: 0 0 10px; text-align: center;">Click here to write a Blog</h3>
                </div>
                @endauth


                @foreach ($posts as $post)
                @php
                $preview = Str::limit($post->content, 300, '...');
                @endphp
                <div style=" margin-bottom: 30px; border-bottom: 1px solid #eee; padding-bottom: 15px;">
                    <h2 style="margin-bottom: 10px;">
                        {{ $post->title }} <span style="font-weight: normal; color: #666;">by {{ $post->user->username ?? 'Unknown' }}</span>
                    </h2>
                    <p style="margin: 0;">{{ $preview }}</p>
                    <div style="margin-top: 10px; display: flex; gap: 10px;">
                        <button onclick="openModal({{ $post->id }})" style="padding: 6px 10px;">Read More</button>
                        @auth
                        <button style="padding: 6px 10px; background-color: #dc3545; color: #fff; border: none; border-radius: 4px;">
                            Edit
                        </button>

                        <button form="delete-form-{{ $post->id }}" type="submit" style="padding: 6px 10px; background-color: #dc3545; color: #fff; border: none; border-radius: 4px;">
                            Delete
                        </button>
                        @endauth
                        <!-- Hidden form for deleting the post with a unique ID -->
                        <form method="post" action="/post/{{ $post->id }}" id="delete-form-{{ $post->id }}" class="hidden">
                            @csrf
                            @method('DELETE')
                        </form>

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



                    @auth
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
                    @endauth
                    <!-- Comments Section -->

                    <div style="margin-top: 20px;">
                        <h4 style="margin-bottom: 10px;">Comments</h4>

                        @foreach ($post->comments as $comment)
                        <div style="margin-bottom: 12px; border-bottom: 1px solid #eee; padding-bottom: 8px;">
                            <div style="display: flex; align-items: flex-start; gap: 10px; margin-bottom: 16px;">
                                <a href="/users/{{ $comment->user->id ?? '#' }}" style="display: inline-block;">
                                    <img src="/image/download.jpg "
                                        alt="User Avatar"
                                        style="width: 48px; height: 48px; border-radius: 50%; object-fit: cover;">
                                </a>

                                <!-- Text Content -->
                                <div>
                                    <!-- Username -->
                                    <a href="/users/{{ $comment->user->id ?? '#' }}"
                                        style="font-weight: 600; text-decoration: none; color: inherit;">
                                        {{ $comment->user->username ?? 'Deleted User' }}
                                    </a>

                                    <!-- Comment Text -->
                                    <p style="margin-top: 4px; margin-bottom: 0;">
                                        {{ $comment->content }}
                                    </p>
                                </div>
                            </div>



                            @auth
                            <!-- Edit Button -->
                            <button style="padding: 6px 10px; background-color: #007bff; color: #fff; border: none; border-radius: 4px;">
                                Edit
                            </button>

                            <!-- Delete Button -->
                            <button onclick="event.preventDefault(); document.getElementById('delete-form-{{ $comment->id }}').submit();"
                                style="padding: 6px 10px; background-color: #dc3545; color: #fff; border: none; border-radius: 4px;">
                                Delete
                            </button>
                            @endauth

                            <!-- Hidden form for deleting the comment with the unique ID -->
                            <form method="POST" action="/comment/{{ $comment->id }}" id="delete-form-{{ $comment->id }}" class="hidden">
                                @csrf
                                @method('DELETE')
                            </form>
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
        <div style="flex: 1; height: 150px; ">
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