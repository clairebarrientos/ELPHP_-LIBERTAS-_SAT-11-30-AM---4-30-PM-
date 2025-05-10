<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{$title}}</title>
</head>

<body>
    <div style="display: flex; align-items: center; justify-content: space-between; padding: 16px 32px; border-bottom: 1px solid #e5e7eb; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">

        <!-- Left: Logo -->
        <div style="display: flex; align-items: center; font-weight: 600; font-family: 'Inter', sans-serif;">
            <a href="/" style="text-decoration: none; color: inherit; display: flex; align-items: center; gap: 10px;">
                <img src="/image/logo.png" alt="Logo" style="height: 40px; width: auto;">
            </a>
            Libertas
        </div>



        <!-- Center: Navigation -->
        <nav style="display: flex; align-items: center; font-size: 28px; font-weight: 600;">



        </nav>

        <!-- Right: Account -->
        <div style="position: relative; display: flex; align-items: center; font-size: 28px; font-weight: 600;"
            onmouseover="this.querySelector('.account-dropdown').style.display='block';"
            onmouseout="this.querySelector('.account-dropdown').style.display='none';">

            <div style="cursor: pointer; font-family: 'Inter', sans-serif; font-weight: 500;">
                <x-nav-link href="/users/{{ auth()->id() }}" :active="request()->is('account')">
                    Account
                </x-nav-link>
            </div>


            <div class="account-dropdown" style="
        display: none;
        position: absolute;
        top: 100%;
        right: 0;
        background-color: white;
        border: 1px solid #e5e7eb;
        box-shadow: 0 2px 6px rgba(0,0,0,0.1);
        min-width: 150px;
        z-index: 1000;
        font-size: 14px;
    ">
                @guest
                <a href="/login" style="display: block; padding: 10px 16px; text-decoration: none; color: #111;">Log In</a>
                <a href="/register" style="display: block; padding: 10px 16px; text-decoration: none; color: #111;">Sign Up</a>
                @endguest
                @auth
                <form action="/logout" method="POST" style="display: block; margin: 0;">
                    @csrf
                    <button type="submit" style="
                padding: 10px 16px;
                background: none;
                border: none;
                color: #111;
                cursor: pointer;
                font-size: 14px;
                text-align: left;
                width: 100%;
            ">
                        Log out
                    </button>
                </form>
                @endauth
            </div>

        </div>




    </div>


    {{$slot}}



</body>

</html>