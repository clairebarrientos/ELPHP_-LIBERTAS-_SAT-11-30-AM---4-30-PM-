<x-layout>
    <x-slot:title>Sign In</x-slot:title>

    <body>
        <div style="display: flex; justify-content: center; padding: 40px;">
            <form method="post" action="/login" style="width: 100%; max-width: 400px; background: #f9f9f9; padding: 30px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1);">
                @csrf

                <div style="margin-bottom: 20px;">
                    <label for="username" style="display: block; margin-bottom: 6px; font-weight: 600;">Username</label>
                    <input value="" type="text" id="username" name="username"
                        style="width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 5px;" required>
                    @error('username')
                    <p style='color:red; font-style:italic;'>{{$message}}</p>
                    @enderror
                </div>


                <div style="margin-bottom: 20px;">
                    <label for="password" style="display: block; margin-bottom: 6px; font-weight: 600;">Password</label>
                    <input value="" type="password" id="password" name="password"
                        style="width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 5px;" required>
                    @error('password')
                    <p style='color:red; font-style:italic;'>{{$message}}</p>
                    @enderror
                </div>

                <button type="submit"
                    style="width: 100%; padding: 12px; background-color: #333; color: #fff; border: none; border-radius: 5px; cursor: pointer;">
                    Sign In
                </button>
            </form>
        </div>
    </body>

</x-layout>