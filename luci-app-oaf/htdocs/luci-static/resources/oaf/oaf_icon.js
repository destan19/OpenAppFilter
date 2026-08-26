(function(window, $) {
    'use strict';

    var iconColors = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4', '#f97316', '#ec4899', '#84cc16', '#6366f1'];
    var iconStatusCache = {};

    function hashColor(value) {
        var text = value ? String(value) : '';
        var hash = 0;

        if (!text) {
            return iconColors[0];
        }

        for (var i = 0; i < text.length; i++) {
            hash = text.charCodeAt(i) + ((hash << 5) - hash);
        }

        return iconColors[Math.abs(hash) % iconColors.length];
    }

    function firstLetter(value) {
        var text = value ? String(value).trim() : '';
        return text ? text.charAt(0).toUpperCase() : '?';
    }

    function appIconSrc(resourceBase, appId) {
        var id = appId === undefined || appId === null ? '' : String(appId).trim();
        return id ? resourceBase + '/oaf/app_icons/' + encodeURIComponent(id) + '.png' : '';
    }

    function createLetterIcon(name, options) {
        options = options || {};
        return $('<span>')
            .addClass(options.className || 'oaf-generated-app-icon')
            .css({
                width: options.size || '20px',
                height: options.size || '20px',
                borderRadius: options.radius || '5px',
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                background: hashColor(name),
                color: '#fff',
                fontSize: options.fontSize || '11px',
                fontWeight: '700',
                flexShrink: 0,
                lineHeight: 1
            })
            .text(firstLetter(name));
    }

    function createAppIcon(appId, name, resourceBase, options) {
        options = options || {};
        var appName = name || '';
        var id = appId === undefined || appId === null ? '' : String(appId).trim();
        var src = appIconSrc(resourceBase, id);
        var iconDisabled = options.icon === 0 || options.icon === '0' || options.hasIcon === false;
        var $icon;

        if (id && iconDisabled) {
            iconStatusCache[id] = 'failed';
        }

        if (id && !iconDisabled && iconStatusCache[id] === 'loaded') {
            return $('<img>')
                .attr({ src: src, alt: appName })
                .css({
                    width: options.size || '20px',
                    height: options.size || '20px',
                    borderRadius: options.radius || '5px',
                    objectFit: options.objectFit || 'cover',
                    display: 'block',
                    flexShrink: 0
                });
        }

        $icon = createLetterIcon(appName, options);
        if (id && !iconDisabled && iconStatusCache[id] !== 'failed') {
            var loader = new Image();
            loader.onload = function() {
                iconStatusCache[id] = 'loaded';
                $icon.replaceWith($('<img>')
                    .attr({ src: src, alt: appName })
                    .css({
                        width: options.size || '20px',
                        height: options.size || '20px',
                        borderRadius: options.radius || '5px',
                        objectFit: options.objectFit || 'cover',
                        display: 'block',
                        flexShrink: 0,
                        border: 'none',
                        boxShadow: 'none'
                    }));
            };
            loader.onerror = function() {
                iconStatusCache[id] = 'failed';
            };
            loader.src = src;
        }

        return $icon;
    }

    window.OAFIcon = {
        colors: iconColors,
        hashColor: hashColor,
        appIconSrc: appIconSrc,
        createLetterIcon: createLetterIcon,
        createAppIcon: createAppIcon
    };
})(window, window.jQuery);
