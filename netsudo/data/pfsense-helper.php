#!/usr/local/bin/php
<?php
/*
 * netsudo pfSense helper.
 *
 * This script is installed on pfSense and is intentionally self-contained:
 * the client can request only named policy profiles already present on the
 * firewall, and the helper enforces duration, source, destination, and alias
 * constraints before touching the pfSense config.
 */

error_reporting(E_ALL);
ini_set('display_errors', 'stderr');

require_once('/etc/inc/config.inc');

define('NETSUDO_POLICY_FILE', '/usr/local/etc/netsudo/policy.json');
define('NETSUDO_STATE_FILE', '/var/db/netsudo/state.json');
define('NETSUDO_AUDIT_FILE', '/var/log/netsudo.log');
define('NETSUDO_PLACEHOLDER_IP', '127.255.255.254');
define('NETSUDO_USER', 'netsudo-helper');

try {
    netsudo_main($argv);
} catch (Throwable $error) {
    netsudo_fail($error->getMessage());
}

function netsudo_main($argv)
{
    $action = isset($argv[1]) ? (string)$argv[1] : '';
    $request = netsudo_read_request();

    if ($action === 'setup') {
        netsudo_cmd_setup($request);
    } elseif ($action === 'grant') {
        netsudo_cmd_grant($request);
    } elseif ($action === 'status') {
        netsudo_cmd_status();
    } elseif ($action === 'revoke') {
        netsudo_cmd_revoke($request);
    } elseif ($action === 'prune') {
        netsudo_cmd_prune();
    }

    throw new RuntimeException('unknown action: ' . $action);
}

function netsudo_cmd_setup($request)
{
    netsudo_ensure_runtime_dirs();
    $policy = isset($request['policy']) ? netsudo_normalize_policy($request['policy']) : netsudo_load_policy();
    netsudo_write_json_file(NETSUDO_POLICY_FILE, $policy, 0600);

    $backup = netsudo_backup_config();
    $state = netsudo_load_state_unlocked();
    $changes = netsudo_apply_state_to_config($policy, $state, 'netsudo setup');

    netsudo_audit('setup', array('changes' => $changes, 'backup' => $backup));
    netsudo_ok(array(
        'message' => 'setup complete',
        'backup' => $backup,
        'changes' => $changes,
    ));
}

function netsudo_cmd_grant($request)
{
    $policy = netsudo_load_policy();
    $profile_name = netsudo_required_string($request, 'profile');
    if (!isset($policy['profiles'][$profile_name])) {
        throw new RuntimeException('unknown profile: ' . $profile_name);
    }

    $profile = $policy['profiles'][$profile_name];
    $source = netsudo_validate_source(netsudo_required_string($request, 'source'));
    $duration = netsudo_required_positive_int($request, 'duration_seconds');
    if ($duration > (int)$profile['max_seconds']) {
        throw new RuntimeException('requested duration exceeds profile maximum');
    }
    $destinations = netsudo_requested_destinations($request, $profile);

    $now = time();
    $grant = array(
        'id' => netsudo_new_grant_id(),
        'profile' => $profile_name,
        'source' => $source,
        'duration_seconds' => $duration,
        'reason' => isset($request['reason']) ? (string)$request['reason'] : '',
        'requested_by' => isset($request['requested_by']) ? (string)$request['requested_by'] : '',
        'request_host' => isset($request['request_host']) ? (string)$request['request_host'] : '',
        'client_platform' => isset($request['client_platform']) ? (string)$request['client_platform'] : '',
        'created_at' => gmdate('c', $now),
        'created_at_epoch' => $now,
        'expires_at' => gmdate('c', $now + $duration),
        'expires_at_epoch' => $now + $duration,
    );
    if ($destinations !== null) {
        $grant['destinations'] = $destinations;
    }

    $mutation = netsudo_mutate_state(function (&$state) use ($grant, $now) {
        $expired = netsudo_prune_state($state, $now);
        $state['grants'][] = $grant;
        return array('expired' => $expired);
    });

    $state = netsudo_load_state_unlocked();
    $changes = netsudo_apply_state_to_config($policy, $state, 'netsudo grant ' . $grant['id']);
    netsudo_kill_grant_states($policy, $mutation['expired']);
    netsudo_audit('grant', $grant);
    netsudo_schedule_prune($duration + 2);

    netsudo_ok(array(
        'grant' => $grant,
        'changes' => $changes,
    ));
}

function netsudo_cmd_status()
{
    $policy = netsudo_load_policy();
    $mutation = netsudo_mutate_state(function (&$state) {
        return array('expired' => netsudo_prune_state($state, time()));
    });

    $state = netsudo_load_state_unlocked();
    $changes = netsudo_apply_state_to_config($policy, $state, 'netsudo status prune');
    netsudo_kill_grant_states($policy, $mutation['expired']);

    netsudo_ok(array(
        'grants' => netsudo_active_grants($state),
        'pruned' => count($mutation['expired']),
        'changes' => $changes,
    ));
}

function netsudo_cmd_revoke($request)
{
    $policy = netsudo_load_policy();
    $target = netsudo_required_string($request, 'grant');

    $mutation = netsudo_mutate_state(function (&$state) use ($target) {
        $revoked = array();
        $remaining = array();

        if ($target === 'all') {
            $revoked = $state['grants'];
        } elseif ($target === 'last') {
            $last_index = null;
            $last_created = -1;
            foreach ($state['grants'] as $index => $grant) {
                $created = isset($grant['created_at_epoch']) ? (int)$grant['created_at_epoch'] : 0;
                if ($created >= $last_created) {
                    $last_created = $created;
                    $last_index = $index;
                }
            }
            foreach ($state['grants'] as $index => $grant) {
                if ($index === $last_index) {
                    $revoked[] = $grant;
                } else {
                    $remaining[] = $grant;
                }
            }
        } else {
            foreach ($state['grants'] as $grant) {
                if ((string)$grant['id'] === $target) {
                    $revoked[] = $grant;
                } else {
                    $remaining[] = $grant;
                }
            }
        }

        if ($target === 'all') {
            $state['grants'] = array();
        } elseif ($target === 'last' || count($revoked) > 0) {
            $state['grants'] = $remaining;
        }

        return array('revoked' => $revoked);
    });

    $state = netsudo_load_state_unlocked();
    $changes = netsudo_apply_state_to_config($policy, $state, 'netsudo revoke ' . $target);
    netsudo_kill_grant_states($policy, $mutation['revoked']);
    netsudo_audit('revoke', array('target' => $target, 'revoked' => $mutation['revoked']));

    $count = count($mutation['revoked']);
    $message = $count === 0 ? 'no matching grants' : 'revoked ' . $count . ' grant(s)';
    netsudo_ok(array(
        'message' => $message,
        'revoked' => $mutation['revoked'],
        'changes' => $changes,
    ));
}

function netsudo_cmd_prune()
{
    $policy = netsudo_load_policy();
    $mutation = netsudo_mutate_state(function (&$state) {
        return array('expired' => netsudo_prune_state($state, time()));
    });

    $state = netsudo_load_state_unlocked();
    $changes = netsudo_apply_state_to_config($policy, $state, 'netsudo prune');
    netsudo_kill_grant_states($policy, $mutation['expired']);

    $count = count($mutation['expired']);
    netsudo_audit('prune', array('expired' => $mutation['expired']));
    netsudo_ok(array(
        'message' => 'pruned ' . $count . ' expired grant(s)',
        'expired' => $mutation['expired'],
        'changes' => $changes,
    ));
}

function netsudo_apply_state_to_config($policy, $state, $message)
{
    $changes = array();
    $changes = array_merge($changes, netsudo_ensure_policy_objects($policy));
    $changes = array_merge($changes, netsudo_rebuild_source_aliases($policy, $state));
    $changes = array_merge($changes, netsudo_rebuild_scoped_grants($policy, $state));

    if (count($changes) > 0) {
        write_config($message);
        netsudo_reload_filter();
    }

    return $changes;
}

function netsudo_ensure_policy_objects($policy)
{
    $changes = array();
    foreach ($policy['profiles'] as $name => $profile) {
        $change = netsudo_set_alias(
            $profile['source_alias'],
            'host',
            array(NETSUDO_PLACEHOLDER_IP),
            'netsudo source profile ' . $name
        );
        if ($change !== null) {
            $changes[] = $change;
        }

        $change = netsudo_set_alias(
            $profile['destination_alias'],
            'network',
            $profile['destinations'],
            'netsudo destination profile ' . $name
        );
        if ($change !== null) {
            $changes[] = $change;
        }

        if ($profile['ports'] !== 'any') {
            $change = netsudo_set_alias(
                $profile['port_alias'],
                'port',
                $profile['ports'],
                'netsudo ports profile ' . $name
            );
            if ($change !== null) {
                $changes[] = $change;
            }
        }

        foreach ($profile['interfaces'] as $interface) {
            $change = netsudo_ensure_rule($name, $profile, $interface);
            if ($change !== null) {
                $changes[] = $change;
            }
        }
    }

    return $changes;
}

function netsudo_rebuild_source_aliases($policy, $state)
{
    $changes = array();
    $active = netsudo_active_grants($state);

    foreach ($policy['profiles'] as $name => $profile) {
        $sources = array();
        foreach ($active as $grant) {
            if ((string)$grant['profile'] !== (string)$name) {
                continue;
            }
            if (netsudo_grant_has_destinations($grant)) {
                continue;
            }
            $sources[(string)$grant['source']] = true;
        }

        $items = array_keys($sources);
        sort($items);
        if (count($items) === 0) {
            $items = array(NETSUDO_PLACEHOLDER_IP);
        }

        $change = netsudo_set_alias(
            $profile['source_alias'],
            'host',
            $items,
            'netsudo source profile ' . $name
        );
        if ($change !== null) {
            $changes[] = $change;
        }
    }

    return $changes;
}

function netsudo_rebuild_scoped_grants($policy, $state)
{
    $changes = array();
    $active = netsudo_active_grants($state);
    $active_aliases = array();
    $active_rules = array();

    foreach ($active as $grant) {
        if (!netsudo_grant_has_destinations($grant)) {
            continue;
        }

        $profile_name = (string)$grant['profile'];
        if (!isset($policy['profiles'][$profile_name])) {
            continue;
        }
        $profile = $policy['profiles'][$profile_name];
        if (!netsudo_grant_destinations_allowed($grant, $profile)) {
            $changes[] = 'skipped scoped grant outside current policy ' . $grant['id'];
            continue;
        }
        $aliases = netsudo_grant_aliases($grant);
        $active_aliases[$aliases['source']] = true;
        $active_aliases[$aliases['destination']] = true;

        $change = netsudo_set_alias(
            $aliases['source'],
            'host',
            array((string)$grant['source']),
            'netsudo scoped source ' . $grant['id']
        );
        if ($change !== null) {
            $changes[] = $change;
        }

        $change = netsudo_set_alias(
            $aliases['destination'],
            'network',
            $grant['destinations'],
            'netsudo scoped destination ' . $grant['id']
        );
        if ($change !== null) {
            $changes[] = $change;
        }

        foreach ($profile['interfaces'] as $interface) {
            $description = 'netsudo-grant:' . $grant['id'] . ':' . $interface;
            $active_rules[$description] = true;
            $change = netsudo_ensure_rule_for_aliases(
                $description,
                $profile,
                $interface,
                $aliases['source'],
                $aliases['destination']
            );
            if ($change !== null) {
                $changes[] = $change;
            }
        }
    }

    $changes = array_merge($changes, netsudo_remove_stale_scoped_objects($active_aliases, $active_rules));
    return $changes;
}

function netsudo_remove_stale_scoped_objects($active_aliases, $active_rules)
{
    global $config;
    $changes = array();
    netsudo_ensure_alias_config();

    $aliases = array();
    foreach ($config['aliases']['alias'] as $alias) {
        $name = isset($alias['name']) ? (string)$alias['name'] : '';
        if (preg_match('/^NETSUDO_G_[A-F0-9]{8}_(SRC|DST)$/', $name) && !isset($active_aliases[$name])) {
            $changes[] = 'removed alias ' . $name;
            continue;
        }
        $aliases[] = $alias;
    }
    $config['aliases']['alias'] = $aliases;

    if (!isset($config['filter']) || !is_array($config['filter'])) {
        $config['filter'] = array();
    }
    if (!isset($config['filter']['rule']) || !is_array($config['filter']['rule'])) {
        $config['filter']['rule'] = array();
    }

    $rules = array();
    foreach ($config['filter']['rule'] as $rule) {
        $description = isset($rule['descr']) ? (string)$rule['descr'] : '';
        if (strpos($description, 'netsudo-grant:') === 0 && !isset($active_rules[$description])) {
            $changes[] = 'removed rule ' . $description;
            continue;
        }
        $rules[] = $rule;
    }
    $config['filter']['rule'] = $rules;

    return $changes;
}

function netsudo_grant_has_destinations($grant)
{
    return isset($grant['destinations']) && is_array($grant['destinations']) && count($grant['destinations']) > 0;
}

function netsudo_grant_destinations_allowed($grant, $profile)
{
    if (!netsudo_grant_has_destinations($grant)) {
        return true;
    }
    foreach ($grant['destinations'] as $destination) {
        if (!netsudo_destination_allowed($destination, $profile['destinations'])) {
            return false;
        }
    }
    return true;
}

function netsudo_grant_aliases($grant)
{
    $id = strtoupper((string)$grant['id']);
    $id = preg_replace('/[^A-Z0-9_]/', '_', $id);
    return array(
        'source' => 'NETSUDO_' . $id . '_SRC',
        'destination' => 'NETSUDO_' . $id . '_DST',
    );
}

function netsudo_set_alias($name, $type, $items, $description)
{
    global $config;
    netsudo_ensure_alias_config();

    $items = array_values(array_unique(array_map('strval', $items)));
    $record = array(
        'name' => $name,
        'type' => $type,
        'address' => implode(' ', $items),
        'descr' => $description,
        'detail' => implode('||', array_fill(0, count($items), 'netsudo')),
    );

    foreach ($config['aliases']['alias'] as $index => $alias) {
        if (isset($alias['name']) && (string)$alias['name'] === (string)$name) {
            $changed = false;
            foreach ($record as $key => $value) {
                if (!isset($alias[$key]) || (string)$alias[$key] !== (string)$value) {
                    $config['aliases']['alias'][$index][$key] = $value;
                    $changed = true;
                }
            }
            return $changed ? 'updated alias ' . $name : null;
        }
    }

    $config['aliases']['alias'][] = $record;
    return 'created alias ' . $name;
}

function netsudo_ensure_rule($profile_name, $profile, $interface)
{
    return netsudo_ensure_rule_for_aliases(
        'netsudo:' . $profile_name . ':' . $interface,
        $profile,
        $interface,
        $profile['source_alias'],
        $profile['destination_alias']
    );
}

function netsudo_ensure_rule_for_aliases($description, $profile, $interface, $source_alias, $destination_alias)
{
    global $config;
    if (!isset($config['filter']) || !is_array($config['filter'])) {
        $config['filter'] = array();
    }
    if (!isset($config['filter']['rule']) || !is_array($config['filter']['rule'])) {
        $config['filter']['rule'] = array();
    }

    $now = (string)time();
    $destination = array('address' => $destination_alias);
    if ($profile['ports'] !== 'any') {
        $destination['port'] = $profile['port_alias'];
    }

    $stable = array(
        'type' => 'pass',
        'interface' => $interface,
        'ipprotocol' => 'inet',
        'statetype' => 'keep state',
        'protocol' => $profile['protocol'],
        'source' => array('address' => $source_alias),
        'destination' => $destination,
        'descr' => $description,
    );

    foreach ($config['filter']['rule'] as $index => $rule) {
        if (!isset($rule['descr']) || (string)$rule['descr'] !== $description) {
            continue;
        }

        if (netsudo_rule_matches($rule, $stable)) {
            return null;
        }

        $config['filter']['rule'][$index] = array_merge(
            array(
                'id' => isset($rule['id']) ? $rule['id'] : '',
                'tracker' => isset($rule['tracker']) ? $rule['tracker'] : netsudo_new_tracker(),
            ),
            $stable,
            array(
                'created' => isset($rule['created']) ? $rule['created'] : array('time' => $now, 'username' => NETSUDO_USER),
                'updated' => array('time' => $now, 'username' => NETSUDO_USER),
            )
        );
        return 'updated rule ' . $description;
    }

    $config['filter']['rule'][] = array_merge(
        array(
            'id' => '',
            'tracker' => netsudo_new_tracker(),
        ),
        $stable,
        array(
            'created' => array('time' => $now, 'username' => NETSUDO_USER),
            'updated' => array('time' => $now, 'username' => NETSUDO_USER),
        )
    );

    return 'created rule ' . $description;
}

function netsudo_rule_matches($rule, $stable)
{
    foreach ($stable as $key => $value) {
        if (!array_key_exists($key, $rule)) {
            return false;
        }
        if (json_encode($rule[$key]) !== json_encode($value)) {
            return false;
        }
    }
    return true;
}

function netsudo_load_policy()
{
    $policy = netsudo_read_json_file(NETSUDO_POLICY_FILE, null);
    if (!is_array($policy)) {
        throw new RuntimeException('policy file not found; run netsudo setup');
    }
    return netsudo_normalize_policy($policy);
}

function netsudo_normalize_policy($policy)
{
    if (!is_array($policy) || !isset($policy['profiles']) || !is_array($policy['profiles'])) {
        throw new RuntimeException('policy must contain profiles');
    }

    $clean = array('version' => 1, 'profiles' => array());
    foreach ($policy['profiles'] as $name => $profile) {
        $name = (string)$name;
        if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/', $name)) {
            throw new RuntimeException('invalid profile name: ' . $name);
        }
        if (!is_array($profile)) {
            throw new RuntimeException('profile must be an object: ' . $name);
        }

        $interfaces = netsudo_string_list($profile, 'interfaces');
        foreach ($interfaces as $interface) {
            if (!preg_match('/^[A-Za-z0-9_]+$/', $interface)) {
                throw new RuntimeException('invalid interface for profile ' . $name);
            }
        }

        $destinations = netsudo_string_list($profile, 'destinations');
        foreach ($destinations as $destination) {
            netsudo_validate_destination($destination);
        }

        $protocol = isset($profile['protocol']) ? strtolower((string)$profile['protocol']) : 'tcp';
        if (!in_array($protocol, array('tcp', 'udp', 'tcp/udp', 'any'), true)) {
            throw new RuntimeException('invalid protocol for profile ' . $name);
        }

        $ports = isset($profile['ports']) ? $profile['ports'] : 'any';
        $port_alias = null;
        if ($ports === 'any') {
            $clean_ports = 'any';
        } else {
            if (!is_array($ports) || count($ports) === 0) {
                throw new RuntimeException('ports must be any or a non-empty list for profile ' . $name);
            }
            $clean_ports = array();
            foreach ($ports as $port) {
                $port = (string)$port;
                netsudo_validate_port($port);
                $clean_ports[] = $port;
            }
            $port_alias = netsudo_validate_alias(netsudo_required_string($profile, 'port_alias'));
        }

        if (!isset($profile['max_seconds']) || !netsudo_is_positive_int_value($profile['max_seconds'])) {
            throw new RuntimeException('invalid max_seconds for profile ' . $name);
        }
        $max_seconds = (int)$profile['max_seconds'];

        $clean['profiles'][$name] = array(
            'description' => isset($profile['description']) ? (string)$profile['description'] : $name,
            'interfaces' => $interfaces,
            'destinations' => $destinations,
            'protocol' => $protocol,
            'ports' => $clean_ports,
            'max_seconds' => $max_seconds,
            'kill_states' => !empty($profile['kill_states']),
            'source_alias' => netsudo_validate_alias(netsudo_required_string($profile, 'source_alias')),
            'destination_alias' => netsudo_validate_alias(netsudo_required_string($profile, 'destination_alias')),
            'port_alias' => $port_alias,
        );
    }

    if (count($clean['profiles']) === 0) {
        throw new RuntimeException('policy requires at least one profile');
    }

    return $clean;
}

function netsudo_string_list($array, $key)
{
    if (!isset($array[$key]) || !is_array($array[$key]) || count($array[$key]) === 0) {
        throw new RuntimeException($key . ' must be a non-empty list');
    }
    $values = array();
    foreach ($array[$key] as $value) {
        $value = trim((string)$value);
        if ($value === '') {
            throw new RuntimeException($key . ' contains an empty value');
        }
        $values[] = $value;
    }
    return $values;
}

function netsudo_validate_alias($alias)
{
    if (!preg_match('/^[A-Za-z][A-Za-z0-9_]{0,30}$/', $alias)) {
        throw new RuntimeException('invalid alias: ' . $alias);
    }
    return $alias;
}

function netsudo_validate_source($source)
{
    $source = trim((string)$source);
    if (filter_var($source, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
        throw new RuntimeException('source must be an IPv4 address');
    }
    return $source;
}

function netsudo_validate_destination($destination)
{
    netsudo_normalize_destination($destination);
}

function netsudo_requested_destinations($request, $profile)
{
    if (!isset($request['destinations']) || $request['destinations'] === null) {
        return null;
    }
    if (!is_array($request['destinations']) || count($request['destinations']) === 0) {
        throw new RuntimeException('destinations must be a non-empty list');
    }

    $destinations = array();
    foreach ($request['destinations'] as $destination) {
        $destination = netsudo_normalize_destination($destination);
        if (!netsudo_destination_allowed($destination, $profile['destinations'])) {
            throw new RuntimeException('destination is outside profile scope: ' . $destination);
        }
        $destinations[$destination] = true;
    }

    $result = array_keys($destinations);
    sort($result);
    return $result;
}

function netsudo_normalize_destination($destination)
{
    $destination = trim((string)$destination);
    if (strpos($destination, '/') === false) {
        if (filter_var($destination, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            throw new RuntimeException('invalid destination: ' . $destination);
        }
        return $destination;
    }

    $parts = explode('/', $destination, 2);
    if (count($parts) !== 2 || filter_var($parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
        throw new RuntimeException('invalid destination: ' . $destination);
    }
    if (!ctype_digit($parts[1])) {
        throw new RuntimeException('invalid destination mask: ' . $destination);
    }
    $mask = (int)$parts[1];
    if ($mask < 0 || $mask > 32) {
        throw new RuntimeException('invalid destination mask: ' . $destination);
    }
    $network = netsudo_ipv4_to_int($parts[0]) & netsudo_ipv4_mask($mask);
    return long2ip($network) . '/' . $mask;
}

function netsudo_destination_allowed($destination, $allowed_destinations)
{
    $requested = netsudo_destination_network($destination);
    foreach ($allowed_destinations as $allowed_destination) {
        $allowed = netsudo_destination_network($allowed_destination);
        if ($requested['mask'] < $allowed['mask']) {
            continue;
        }
        $mask = netsudo_ipv4_mask($allowed['mask']);
        if (($requested['network'] & $mask) === $allowed['network']) {
            return true;
        }
    }
    return false;
}

function netsudo_destination_network($destination)
{
    $destination = netsudo_normalize_destination($destination);
    if (strpos($destination, '/') === false) {
        return array(
            'network' => netsudo_ipv4_to_int($destination),
            'mask' => 32,
        );
    }

    $parts = explode('/', $destination, 2);
    $mask = (int)$parts[1];
    return array(
        'network' => netsudo_ipv4_to_int($parts[0]) & netsudo_ipv4_mask($mask),
        'mask' => $mask,
    );
}

function netsudo_ipv4_to_int($ip)
{
    $packed = inet_pton($ip);
    if ($packed === false) {
        throw new RuntimeException('invalid IPv4 address: ' . $ip);
    }
    $unpacked = unpack('N', $packed);
    return (int)$unpacked[1];
}

function netsudo_ipv4_mask($bits)
{
    $bits = (int)$bits;
    if ($bits === 0) {
        return 0;
    }
    return (0xffffffff << (32 - $bits)) & 0xffffffff;
}

function netsudo_validate_port($port)
{
    if (strpos($port, '-') !== false) {
        $parts = explode('-', $port, 2);
        if (count($parts) !== 2 || !ctype_digit($parts[0]) || !ctype_digit($parts[1])) {
            throw new RuntimeException('invalid port range: ' . $port);
        }
        $start = (int)$parts[0];
        $end = (int)$parts[1];
        if ($start < 1 || $end > 65535 || $start > $end) {
            throw new RuntimeException('invalid port range: ' . $port);
        }
        return;
    }

    if (!ctype_digit($port) || (int)$port < 1 || (int)$port > 65535) {
        throw new RuntimeException('invalid port: ' . $port);
    }
}

function netsudo_required_string($array, $key)
{
    if (!is_array($array) || !isset($array[$key]) || trim((string)$array[$key]) === '') {
        throw new RuntimeException('missing required field: ' . $key);
    }
    return trim((string)$array[$key]);
}

function netsudo_required_positive_int($array, $key)
{
    if (!is_array($array) || !isset($array[$key])) {
        throw new RuntimeException('missing required field: ' . $key);
    }
    if (!netsudo_is_positive_int_value($array[$key])) {
        throw new RuntimeException($key . ' must be a positive integer');
    }
    $value = (int)$array[$key];
    return $value;
}

function netsudo_is_positive_int_value($value)
{
    if (is_int($value)) {
        return $value > 0;
    }
    if (is_string($value) && ctype_digit($value)) {
        return (int)$value > 0;
    }
    return false;
}

function netsudo_mutate_state($callback)
{
    netsudo_ensure_runtime_dirs();
    $lock = fopen(NETSUDO_STATE_FILE . '.lock', 'c');
    if ($lock === false) {
        throw new RuntimeException('could not open state lock');
    }

    try {
        if (!flock($lock, LOCK_EX)) {
            throw new RuntimeException('could not lock state');
        }
        $state = netsudo_load_state_unlocked();
        $result = $callback($state);
        netsudo_save_state_unlocked($state);
        flock($lock, LOCK_UN);
        fclose($lock);
        return $result;
    } catch (Throwable $error) {
        flock($lock, LOCK_UN);
        fclose($lock);
        throw $error;
    }
}

function netsudo_load_state_unlocked()
{
    $state = netsudo_read_json_file(NETSUDO_STATE_FILE, array('grants' => array()));
    if (!is_array($state) || !isset($state['grants']) || !is_array($state['grants'])) {
        $state = array('grants' => array());
    }

    $active = array();
    foreach ($state['grants'] as $grant) {
        if (is_array($grant) && isset($grant['id'], $grant['profile'], $grant['source'], $grant['expires_at_epoch'])) {
            $active[] = $grant;
        }
    }
    return array('grants' => $active);
}

function netsudo_save_state_unlocked($state)
{
    netsudo_write_json_file(NETSUDO_STATE_FILE, $state, 0600);
}

function netsudo_prune_state(&$state, $now)
{
    $expired = array();
    $active = array();
    foreach ($state['grants'] as $grant) {
        if ((int)$grant['expires_at_epoch'] <= $now) {
            $expired[] = $grant;
        } else {
            $active[] = $grant;
        }
    }
    $state['grants'] = $active;
    return $expired;
}

function netsudo_active_grants($state)
{
    $now = time();
    $active = array();
    foreach ($state['grants'] as $grant) {
        if ((int)$grant['expires_at_epoch'] > $now) {
            $active[] = $grant;
        }
    }
    usort($active, function ($left, $right) {
        return ((int)$left['expires_at_epoch']) <=> ((int)$right['expires_at_epoch']);
    });
    return $active;
}

function netsudo_kill_grant_states($policy, $grants)
{
    $seen = array();
    foreach ($grants as $grant) {
        if (!isset($grant['profile'], $grant['source'])) {
            continue;
        }
        $profile_name = (string)$grant['profile'];
        if (!isset($policy['profiles'][$profile_name]) || empty($policy['profiles'][$profile_name]['kill_states'])) {
            continue;
        }
        $source = (string)$grant['source'];
        if (isset($seen[$source])) {
            continue;
        }
        $seen[$source] = true;
        exec('/sbin/pfctl -k ' . escapeshellarg($source) . ' >/dev/null 2>&1');
    }
}

function netsudo_schedule_prune($seconds)
{
    $delay = max(1, (int)$seconds);
    $inner = 'sleep ' . $delay . '; /usr/local/bin/php ' . escapeshellarg(__FILE__) . ' prune >/dev/null 2>&1';
    exec('nohup sh -c ' . escapeshellarg($inner) . ' >/dev/null 2>&1 &');
}

function netsudo_ensure_alias_config()
{
    global $config;
    if (!isset($config['aliases']) || !is_array($config['aliases'])) {
        $config['aliases'] = array();
    }
    if (!isset($config['aliases']['alias']) || !is_array($config['aliases']['alias'])) {
        $config['aliases']['alias'] = array();
    }
}

function netsudo_reload_filter()
{
    exec('/etc/rc.filter_configure >/dev/null 2>&1');
}

function netsudo_backup_config()
{
    $source = '/cf/conf/config.xml';
    $destination = '/cf/conf/config.xml.pre-netsudo-' . date('YmdHis');
    if (!is_readable($source)) {
        return null;
    }
    if (!copy($source, $destination)) {
        throw new RuntimeException('failed to create pfSense config backup');
    }
    return $destination;
}

function netsudo_new_grant_id()
{
    return 'g_' . bin2hex(random_bytes(4));
}

function netsudo_new_tracker()
{
    return (string)random_int(1000000000, 2147483647);
}

function netsudo_audit($event, $payload)
{
    $record = array(
        'time' => time(),
        'event' => $event,
        'payload' => $payload,
    );
    file_put_contents(NETSUDO_AUDIT_FILE, json_encode($record, JSON_UNESCAPED_SLASHES) . "\n", FILE_APPEND | LOCK_EX);
    @chmod(NETSUDO_AUDIT_FILE, 0600);
}

function netsudo_read_request()
{
    $raw = stream_get_contents(STDIN);
    if ($raw === false || trim($raw) === '') {
        return array();
    }
    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        throw new RuntimeException('request payload must be JSON');
    }
    return $decoded;
}

function netsudo_read_json_file($path, $default)
{
    if (!file_exists($path)) {
        return $default;
    }
    $raw = file_get_contents($path);
    if ($raw === false || trim($raw) === '') {
        return $default;
    }
    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        throw new RuntimeException('invalid JSON file: ' . $path);
    }
    return $decoded;
}

function netsudo_write_json_file($path, $value, $mode)
{
    $json = json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if ($json === false) {
        throw new RuntimeException('failed to encode JSON');
    }
    $tmp = $path . '.tmp.' . getmypid();
    if (file_put_contents($tmp, $json . "\n", LOCK_EX) === false) {
        throw new RuntimeException('failed to write ' . $path);
    }
    @chmod($tmp, $mode);
    if (!rename($tmp, $path)) {
        @unlink($tmp);
        throw new RuntimeException('failed to replace ' . $path);
    }
    @chmod($path, $mode);
}

function netsudo_ensure_runtime_dirs()
{
    foreach (array('/usr/local/etc/netsudo', '/var/db/netsudo') as $dir) {
        if (!is_dir($dir) && !mkdir($dir, 0700, true)) {
            throw new RuntimeException('failed to create directory: ' . $dir);
        }
    }
}

function netsudo_ok($payload)
{
    $payload = array_merge(array('ok' => true), $payload);
    echo json_encode($payload, JSON_UNESCAPED_SLASHES) . "\n";
    exit(0);
}

function netsudo_fail($message)
{
    echo json_encode(array('ok' => false, 'error' => $message), JSON_UNESCAPED_SLASHES) . "\n";
    exit(1);
}
