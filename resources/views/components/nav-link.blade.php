@props(['active' => false])



<!-- Horizontally Aligned -->
<div style="display: flex; align-items: center; gap: 12px;">
    <a style="
        text-decoration: none;
        color: {{ $active ? '#000' : '#555' }};
        font-weight: 500;
        font-family: 'Inter', sans-serif;
        padding: 6px 12px;
    " {{ $attributes }}>
        {{ $slot }}
    </a>
</div>