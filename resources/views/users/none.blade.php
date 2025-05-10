<x-layout>
    <x-slot:title>Sign in</x-slot:title>


    <body style="margin: 20px; font-family: sans-serif;">

        <div style="position: relative; display: inline-block;">
            <button onclick="toggleDropdown()" style="padding: 10px 20px; cursor: pointer;">
                Menu ▼
            </button>

            <ul id="dropdown"
                style="
                display: none;
                position: absolute;
                top: 100%;
                left: 0;
                background: white;
                border: 1px solid #ccc;
                padding: 0;
                margin: 0;
                list-style: none;
                width: 200px;
                max-height: 200px; /* 👈 limit height */
                overflow-y: auto;   /* 👈 enable vertical scroll */
                box-shadow: 0 4px 8px rgba(0,0,0,0.1);
                z-index: 100;
            ">

                @foreach ($user as $users)
                <li style="padding: 10px; border-bottom: 1px solid #eee; cursor: pointer;">
                    <a href="/users/account/{{ $users->id }}" style="text-decoration: none; color: black;">
                        {{ $users->username }}
                    </a>
                </li>
                @endforeach

            </ul>
        </div>

        <script>
            function toggleDropdown() {
                var dropdown = document.getElementById("dropdown");
                dropdown.style.display = dropdown.style.display === "block" ? "none" : "block";
            }
        </script>

    </body>







</x-layout>