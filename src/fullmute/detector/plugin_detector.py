import re
from typing import List, Tuple
from fullmute.utils.logger import setup_logger

logger = setup_logger()

class PluginDetector:
    def __init__(self, url: str, headers: dict, html: str):
        self.url = url
        self.headers = headers
        self.html = html

    def detect_plugins(self) -> dict:
        results = {}


        wp_plugins = self.detect_wordpress_plugins()
        if wp_plugins:
            results['wordpress'] = wp_plugins


        wp_themes = self.detect_wordpress_themes()
        if wp_themes:
            if 'wordpress' not in results:
                results['wordpress'] = []

            results['wordpress_themes'] = wp_themes


        joomla_exts = self.detect_joomla_extensions()
        if joomla_exts:
            results['joomla'] = joomla_exts

        drupal_mods = self.detect_drupal_modules()
        if drupal_mods:
            results['drupal'] = drupal_mods

        bitrix_comps = self.detect_bitrix_components()
        if bitrix_comps:
            results['bitrix'] = bitrix_comps

        return results

    def detect_wordpress_plugins(self) -> List[Tuple[str, str]]:
        plugins = set()


        plugin_pattern1 = r'/wp-content/plugins/([^/\"\'>]+)/'
        matches1 = re.findall(plugin_pattern1, self.html, re.IGNORECASE)
        for plugin in matches1:

            version = self._extract_version_from_path(f'/wp-content/plugins/{plugin}/')
            plugins.add((plugin, version))


        plugin_pattern2 = r'wp-content[\/\\]plugins[\/\\]([^\/\\\"\'>\s]+)/'
        matches2 = re.findall(plugin_pattern2, self.html, re.IGNORECASE)
        for plugin in matches2:
            version = self._extract_version_from_path(f'wp-content/plugins/{plugin}/')
            plugins.add((plugin, version))


        resource_pattern = r'(?:href|src)=["\'][^"\']*wp-content[\/\\]plugins[\/\\]([^\/\\\"\'>\s]+)[\/\\][^"\']*["\']'
        matches3 = re.findall(resource_pattern, self.html, re.IGNORECASE)
        for plugin in matches3:
            version = self._extract_version_from_path(f'wp-content/plugins/{plugin}/')
            plugins.add((plugin, version))


        json_pattern = r'["\']wp[-_]?(?:plugin|extension)["\']\s*:\s*["\']([^"\']+)["\']'
        matches4 = re.findall(json_pattern, self.html, re.IGNORECASE)
        for plugin in matches4:

            clean_plugin = re.sub(r'[^\w\-]', '', plugin)
            if len(clean_plugin) > 2:
                version = self._extract_version_from_text(clean_plugin, self.html)
                plugins.add((clean_plugin, version))

        return list(plugins)

    def detect_wordpress_themes(self) -> List[Tuple[str, str]]:
        themes = set()


        theme_pattern1 = r'/wp-content/themes/([^/\"\'>]+)/'
        matches1 = re.findall(theme_pattern1, self.html, re.IGNORECASE)
        for theme in matches1:
            version = self._extract_version_from_path(f'/wp-content/themes/{theme}/')
            themes.add((theme, version))


        theme_pattern2 = r'wp-content[\/\\]themes[\/\\]([^\/\\\"\'>\s]+)/'
        matches2 = re.findall(theme_pattern2, self.html, re.IGNORECASE)
        for theme in matches2:
            version = self._extract_version_from_path(f'wp-content/themes/{theme}/')
            themes.add((theme, version))


        resource_pattern = r'(?:href|src)=["\'][^"\']*wp-content[\/\\]themes[\/\\]([^\/\\\"\'>\s]+)[\/\\][^"\']*["\']'
        matches3 = re.findall(resource_pattern, self.html, re.IGNORECASE)
        for theme in matches3:
            version = self._extract_version_from_path(f'wp-content/themes/{theme}/')
            themes.add((theme, version))


        meta_pattern = r'(?:name|class)=["\'][^"\']*["\'][^>]*>\s*[^<]*["\']([^"\'>\s]+)["\']'

        generator_pattern = r'content=["\'][^"\']*by[^"\']*([^"\'>\s]+)[^"\']*["\'][^>]*name=["\'][^"\']*generator'
        matches4 = re.findall(generator_pattern, self.html, re.IGNORECASE)
        for theme in matches4:
            clean_theme = re.sub(r'[^\w\-]', '', theme)
            if len(clean_theme) > 2:
                version = self._extract_version_from_text(clean_theme, self.html)
                themes.add((clean_theme, version))

        return list(themes)

    def detect_joomla_extensions(self) -> List[Tuple[str, str]]:
        extensions = set()


        comp_pattern = r'/components/com_([^/\"\'>]+)/'
        matches1 = re.findall(comp_pattern, self.html, re.IGNORECASE)
        for ext in matches1:
            version = self._extract_version_from_path(f'/components/com_{ext}/')
            extensions.add((f"com_{ext}", version))

        mod_pattern = r'/modules/mod_([^/\"\'>]+)/'
        matches2 = re.findall(mod_pattern, self.html, re.IGNORECASE)
        for ext in matches2:
            version = self._extract_version_from_path(f'/modules/mod_{ext}/')
            extensions.add((f"mod_{ext}", version))

        plg_pattern = r'/plugins/([^/\"\'>]+)/'
        matches3 = re.findall(plg_pattern, self.html, re.IGNORECASE)
        for ext in matches3:
            version = self._extract_version_from_path(f'/plugins/{ext}/')
            extensions.add((ext, version))

        return list(extensions)

    def detect_drupal_modules(self) -> List[Tuple[str, str]]:
        modules = set()


        mod_pattern = r'/modules/([^/\"\'>\s]+)/'
        matches = re.findall(mod_pattern, self.html, re.IGNORECASE)
        for mod in matches:

            if mod not in ['system', 'user', 'node', 'views']:
                version = self._extract_version_from_path(f'/modules/{mod}/')
                modules.add((mod, version))


        contrib_pattern = r'/sites/(?:all/)?modules/contrib/([^/\"\'>\s]+)/'
        contrib_matches = re.findall(contrib_pattern, self.html, re.IGNORECASE)
        for mod in contrib_matches:
            version = self._extract_version_from_path(f'/sites/all/modules/contrib/{mod}/')
            modules.add((mod, version))

        return list(modules)

    def _extract_version_from_path(self, path_fragment: str) -> str:


        escaped_fragment = re.escape(path_fragment.replace('/', '/'))
        version_patterns = [
            rf'{escaped_fragment}[^"\']*?([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            rf'{escaped_fragment}[^"\']*?v([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            rf'{escaped_fragment}[^"\']*?([0-9]+_[0-9]+(?:_[0-9]+)?)',
        ]

        for pattern in version_patterns:
            match = re.search(pattern, self.html, re.IGNORECASE)
            if match:
                return match.group(1)

        return ""

    def _extract_version_from_text(self, item_name: str, text: str) -> str:

        patterns = [
            rf'{re.escape(item_name)}[^a-zA-Z0-9]*v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            rf'{re.escape(item_name)}[^a-zA-Z0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            rf'({item_name}).*?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match and len(match.groups()) > 0:

                version_group = match.groups()[-1]
                if re.match(r'^[0-9]+(\.[0-9]+)*$', version_group):
                    return version_group

        return ""

    def _is_likely_plugin(self, name: str) -> bool:

        plugin_indicators = [
            'wp_', 'wc_', 'woocom', 'contact', 'social', 'seo', 'cache',
            'backup', 'security', 'gallery', 'slider', 'form', 'captcha'
        ]

        name_lower = name.lower()
        return any(indicator in name_lower for indicator in plugin_indicators) or len(name) <= 50

    def detect_bitrix_components(self) -> List[Tuple[str, str]]:
        components = set()


        comp_pattern = r'/bitrix/components/([^/\"\'\s]+)/([^/\"\'\s]+)/'
        matches = re.findall(comp_pattern, self.html, re.IGNORECASE)
        for vendor, comp_name in matches:
            full_comp = f"{vendor}/{comp_name}"
            version = self._extract_version_from_path(f'/bitrix/components/{vendor}/{comp_name}/')
            components.add((full_comp, version))


        bitrix_comp_pattern = r'bitrix:([^\'\"\s>]+)'
        matches = re.findall(bitrix_comp_pattern, self.html, re.IGNORECASE)
        for comp in matches:
            version = self._extract_version_from_text(comp, self.html)
            components.add((comp, version))


        template_pattern = r'/bitrix/templates/([^/\"\'\s]+)/'
        matches = re.findall(template_pattern, self.html, re.IGNORECASE)
        for template in matches:
            components.add((f"template:{template}", ""))


        include_pattern = r'IncludeComponent\(\s*"([^"]+)"'
        matches = re.findall(include_pattern, self.html, re.IGNORECASE)
        for comp in matches:
            version = self._extract_version_from_text(comp, self.html)
            components.add((comp, version))

        return list(components)
