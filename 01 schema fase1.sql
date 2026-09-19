-- ============================================================
-- NEXORA CONTROL — NUEVA CAMPAÑA — ETAPA 2 / FASE 1
-- Roles y menús + carga de bases + asignación automática
-- Ejecutar completo en: Supabase → SQL Editor → New query → Run
-- ============================================================

create extension if not exists pgcrypto;

-- ------------------------------------------------------------
-- TABLAS
-- ------------------------------------------------------------

create table if not exists n_usuarios (
  id uuid primary key default gen_random_uuid(),
  nombre text not null,
  usuario text not null unique,
  password_hash text not null,
  rol text not null check (rol in ('dueño','encargado','trabajador')),
  activo boolean not null default true,
  trabaja_sabado boolean not null default false,
  observaciones text,
  creado_en timestamptz not null default now(),
  actualizado_en timestamptz not null default now()
);

create table if not exists n_campanas (
  id uuid primary key default gen_random_uuid(),
  nombre text not null,
  activa boolean not null default true,
  creada_por uuid references n_usuarios(id),
  creada_en timestamptz not null default now()
);

create table if not exists n_equipos (
  id uuid primary key default gen_random_uuid(),
  codigo text not null unique,           -- PC-001, PC-002...
  device_token text not null unique,     -- generado y guardado en el navegador
  ultimo_usuario_id uuid references n_usuarios(id),
  ultima_actividad timestamptz,
  estado text not null default 'desconectado' check (estado in ('conectado','desconectado')),
  creado_en timestamptz not null default now()
);

create table if not exists n_bases (
  id uuid primary key default gen_random_uuid(),
  campana_id uuid not null references n_campanas(id),
  nombre_archivo text,
  total_registros integer not null default 0,
  duplicados_descartados integer not null default 0,
  cargado_por uuid references n_usuarios(id),
  cargado_en timestamptz not null default now()
);

create table if not exists n_registros (
  id uuid primary key default gen_random_uuid(),
  base_id uuid references n_bases(id),
  campana_id uuid not null references n_campanas(id),
  datos jsonb not null,
  hash_dedupe text,
  estado text not null default 'ingresado' check (estado in (
    'ingresado','asignado','trabajado','restante','buzon','no_disponible',
    'contesto_colgo','segunda_llamada','otro','exitoso','no_exitoso'
  )),
  trabajador_id uuid references n_usuarios(id),
  equipo_id uuid references n_equipos(id),
  asignado_en timestamptz,
  resultado text,
  observaciones text,
  monto numeric,
  creado_en timestamptz not null default now(),
  actualizado_en timestamptz not null default now()
);

create unique index if not exists n_registros_dedupe_uq
  on n_registros(campana_id, hash_dedupe) where hash_dedupe is not null;

create index if not exists n_registros_estado_idx on n_registros(campana_id, estado);
create index if not exists n_registros_trabajador_idx on n_registros(trabajador_id);

create table if not exists n_sesiones (
  id uuid primary key default gen_random_uuid(),
  usuario_id uuid not null references n_usuarios(id),
  token text not null unique,
  equipo_id uuid references n_equipos(id),
  creado_en timestamptz not null default now(),
  expira_en timestamptz not null
);

create table if not exists n_auditoria (
  id uuid primary key default gen_random_uuid(),
  usuario_id uuid references n_usuarios(id),
  rol text,
  accion text not null,
  tabla_afectada text,
  registro_id text,
  valor_anterior jsonb,
  valor_nuevo jsonb,
  creado_en timestamptz not null default now()
);

-- ------------------------------------------------------------
-- RLS: cerrado por completo. Todo el acceso pasa por RPC (security definer).
-- ------------------------------------------------------------
alter table n_usuarios enable row level security;
alter table n_campanas enable row level security;
alter table n_equipos enable row level security;
alter table n_bases enable row level security;
alter table n_registros enable row level security;
alter table n_sesiones enable row level security;
alter table n_auditoria enable row level security;
-- (sin policies = nadie entra directo por PostgREST; solo vía funciones RPC)

-- ------------------------------------------------------------
-- FUNCIÓN INTERNA: validar sesión y devolver usuario
-- ------------------------------------------------------------
create or replace function n_fn_sesion(p_token text)
returns n_usuarios
language plpgsql
security definer
set search_path = public
as $$
declare
  v_usuario n_usuarios;
begin
  select u.* into v_usuario
  from n_sesiones s
  join n_usuarios u on u.id = s.usuario_id
  where s.token = p_token
    and s.expira_en > now()
    and u.activo = true;

  if v_usuario.id is null then
    raise exception 'SESION_INVALIDA';
  end if;

  update n_sesiones set expira_en = now() + interval '8 hours' where token = p_token;

  return v_usuario;
end;
$$;

-- ------------------------------------------------------------
-- INSTALACIÓN: crea el primer dueño (solo si no existe ningún usuario)
-- ------------------------------------------------------------
create or replace function n_fn_instalar(p_nombre text, p_usuario text, p_password text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_id uuid;
begin
  if exists (select 1 from n_usuarios) then
    raise exception 'YA_INSTALADO';
  end if;

  insert into n_usuarios (nombre, usuario, password_hash, rol)
  values (p_nombre, lower(p_usuario), crypt(p_password, gen_salt('bf')), 'dueño')
  returning id into v_id;

  insert into n_auditoria (usuario_id, rol, accion, tabla_afectada, registro_id)
  values (v_id, 'dueño', 'INSTALACION', 'n_usuarios', v_id::text);

  return jsonb_build_object('ok', true, 'usuario_id', v_id);
end;
$$;

-- ------------------------------------------------------------
-- LOGIN: valida password, registra/actualiza equipo, crea sesión
-- ------------------------------------------------------------
create or replace function n_fn_login(p_usuario text, p_password text, p_device_token text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_usuario n_usuarios;
  v_equipo n_equipos;
  v_token text;
  v_siguiente int;
  v_codigo text;
begin
  select * into v_usuario from n_usuarios
   where usuario = lower(p_usuario) and activo = true;

  if v_usuario.id is null or v_usuario.password_hash <> crypt(p_password, v_usuario.password_hash) then
    raise exception 'CREDENCIALES_INVALIDAS';
  end if;

  select * into v_equipo from n_equipos where device_token = p_device_token;
  if v_equipo.id is null then
    select coalesce(max(substring(codigo from 4)::int), 0) + 1 into v_siguiente from n_equipos;
    v_codigo := 'PC-' || lpad(v_siguiente::text, 3, '0');
    insert into n_equipos (codigo, device_token, ultimo_usuario_id, ultima_actividad, estado)
    values (v_codigo, p_device_token, v_usuario.id, now(), 'conectado')
    returning * into v_equipo;
  else
    update n_equipos set ultimo_usuario_id = v_usuario.id, ultima_actividad = now(), estado = 'conectado'
    where id = v_equipo.id returning * into v_equipo;
  end if;

  v_token := encode(gen_random_bytes(24), 'hex');
  insert into n_sesiones (usuario_id, token, equipo_id, expira_en)
  values (v_usuario.id, v_token, v_equipo.id, now() + interval '8 hours');

  insert into n_auditoria (usuario_id, rol, accion, tabla_afectada, registro_id)
  values (v_usuario.id, v_usuario.rol, 'LOGIN', 'n_usuarios', v_usuario.id::text);

  return jsonb_build_object(
    'token', v_token,
    'nombre', v_usuario.nombre,
    'usuario', v_usuario.usuario,
    'rol', v_usuario.rol,
    'equipo_codigo', v_equipo.codigo
  );
end;
$$;

create or replace function n_fn_verificar_sesion(p_token text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_usuario n_usuarios;
begin
  v_usuario := n_fn_sesion(p_token);
  return jsonb_build_object('nombre', v_usuario.nombre, 'usuario', v_usuario.usuario, 'rol', v_usuario.rol);
exception when others then
  return jsonb_build_object('error', 'SESION_INVALIDA');
end;
$$;

create or replace function n_fn_latido(p_token text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_usuario n_usuarios;
begin
  v_usuario := n_fn_sesion(p_token);
  update n_equipos e set ultima_actividad = now(), estado = 'conectado'
  from n_sesiones s
  where s.token = p_token and s.equipo_id = e.id;
end;
$$;

-- ------------------------------------------------------------
-- PERSONAL: crear / listar / editar usuarios (dueño; encargado solo lectura)
-- ------------------------------------------------------------
create or replace function n_fn_crear_usuario(
  p_token text, p_nombre text, p_usuario text, p_password text,
  p_rol text, p_trabaja_sabado boolean, p_observaciones text
) returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_actor n_usuarios;
  v_id uuid;
begin
  v_actor := n_fn_sesion(p_token);
  if v_actor.rol <> 'dueño' then
    raise exception 'PERMISO_DENEGADO';
  end if;
  if p_rol not in ('encargado','trabajador') then
    raise exception 'ROL_INVALIDO';
  end if;

  insert into n_usuarios (nombre, usuario, password_hash, rol, trabaja_sabado, observaciones)
  values (p_nombre, lower(p_usuario), crypt(p_password, gen_salt('bf')), p_rol, p_trabaja_sabado, p_observaciones)
  returning id into v_id;

  insert into n_auditoria (usuario_id, rol, accion, tabla_afectada, registro_id, valor_nuevo)
  values (v_actor.id, v_actor.rol, 'CREAR_USUARIO', 'n_usuarios', v_id::text,
          jsonb_build_object('nombre', p_nombre, 'usuario', p_usuario, 'rol', p_rol));

  return jsonb_build_object('ok', true, 'id', v_id);
end;
$$;

create or replace function n_fn_listar_usuarios(p_token text)
returns setof n_usuarios
language plpgsql
security definer
set search_path = public
as $$
declare
  v_actor n_usuarios;
begin
  v_actor := n_fn_sesion(p_token);
  if v_actor.rol not in ('dueño','encargado') then
    raise exception 'PERMISO_DENEGADO';
  end if;
  return query select * from n_usuarios order by rol, nombre;
end;
$$;

create or replace function n_fn_editar_usuario(
  p_token text, p_usuario_id uuid, p_nombre text, p_activo boolean,
  p_trabaja_sabado boolean, p_observaciones text, p_password text
) returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_actor n_usuarios;
  v_anterior n_usuarios;
begin
  v_actor := n_fn_sesion(p_token);
  if v_actor.rol <> 'dueño' then
    raise exception 'PERMISO_DENEGADO';
  end if;

  select * into v_anterior from n_usuarios where id = p_usuario_id;

  update n_usuarios set
    nombre = coalesce(p_nombre, nombre),
    activo = coalesce(p_activo, activo),
    trabaja_sabado = coalesce(p_trabaja_sabado, trabaja_sabado),
    observaciones = coalesce(p_observaciones, observaciones),
    password_hash = case when p_password is not null and p_password <> ''
                          then crypt(p_password, gen_salt('bf')) else password_hash end,
    actualizado_en = now()
  where id = p_usuario_id;

  insert into n_auditoria (usuario_id, rol, accion, tabla_afectada, registro_id, valor_anterior)
  values (v_actor.id, v_actor.rol, 'EDITAR_USUARIO', 'n_usuarios', p_usuario_id::text, to_jsonb(v_anterior));

  return jsonb_build_object('ok', true);
end;
$$;

-- ------------------------------------------------------------
-- CAMPAÑA: crear nueva (limpia, desactiva las anteriores) / consultar activa
-- ------------------------------------------------------------
create or replace function n_fn_crear_campana(p_token text, p_nombre text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_actor n_usuarios;
  v_id uuid;
begin
  v_actor := n_fn_sesion(p_token);
  if v_actor.rol <> 'dueño' then
    raise exception 'PERMISO_DENEGADO';
  end if;

  update n_campanas set activa = false where activa = true;

  insert into n_campanas (nombre, creada_por, activa)
  values (p_nombre, v_actor.id, true)
  returning id into v_id;

  insert into n_auditoria (usuario_id, rol, accion, tabla_afectada, registro_id, valor_nuevo)
  values (v_actor.id, v_actor.rol, 'CREAR_CAMPANA', 'n_campanas', v_id::text, jsonb_build_object('nombre', p_nombre));

  return jsonb_build_object('ok', true, 'id', v_id);
end;
$$;

create or replace function n_fn_campana_activa(p_token text)
returns n_campanas
language plpgsql
security definer
set search_path = public
as $$
declare
  v_actor n_usuarios;
  v_campana n_campanas;
begin
  v_actor := n_fn_sesion(p_token);
  select * into v_campana from n_campanas where activa = true order by creada_en desc limit 1;
  return v_campana;
end;
$$;

create or replace function n_fn_listar_campanas(p_token text)
returns setof n_campanas
language plpgsql
security definer
set search_path = public
as $$
declare
  v_actor n_usuarios;
begin
  v_actor := n_fn_sesion(p_token);
  if v_actor.rol <> 'dueño' then
    raise exception 'PERMISO_DENEGADO';
  end if;
  return query select * from n_campanas order by creada_en desc;
end;
$$;

-- ------------------------------------------------------------
-- BASES: cargar registros (dueño/encargado), con deduplicación
-- p_registros: jsonb array, cada elemento es el registro tal cual (columnas libres)
-- p_campo_dedupe: nombre del campo dentro de cada registro usado para no duplicar (ej. "telefono")
-- ------------------------------------------------------------
create or replace function n_fn_cargar_base(
  p_token text, p_campana_id uuid, p_nombre_archivo text,
  p_registros jsonb, p_campo_dedupe text
) returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_actor n_usuarios;
  v_base_id uuid;
  v_total int := 0;
  v_dup int := 0;
  v_item jsonb;
  v_hash text;
begin
  v_actor := n_fn_sesion(p_token);
  if v_actor.rol not in ('dueño','encargado') then
    raise exception 'PERMISO_DENEGADO';
  end if;

  insert into n_bases (campana_id, nombre_archivo, cargado_por)
  values (p_campana_id, p_nombre_archivo, v_actor.id)
  returning id into v_base_id;

  for v_item in select * from jsonb_array_elements(p_registros) loop
    v_hash := case when p_campo_dedupe is not null and p_campo_dedupe <> ''
                   then md5(coalesce(v_item ->> p_campo_dedupe, ''))
                   else null end;

    begin
      insert into n_registros (base_id, campana_id, datos, hash_dedupe, estado)
      values (v_base_id, p_campana_id, v_item, v_hash, 'ingresado');
      v_total := v_total + 1;
    exception when unique_violation then
      v_dup := v_dup + 1;
    end;
  end loop;

  update n_bases set total_registros = v_total, duplicados_descartados = v_dup where id = v_base_id;

  insert into n_auditoria (usuario_id, rol, accion, tabla_afectada, registro_id, valor_nuevo)
  values (v_actor.id, v_actor.rol, 'CARGAR_BASE', 'n_bases', v_base_id::text,
          jsonb_build_object('total', v_total, 'duplicados', v_dup));

  return jsonb_build_object('ok', true, 'base_id', v_base_id, 'insertados', v_total, 'duplicados', v_dup);
end;
$$;

create or replace function n_fn_resumen_campana(p_token text, p_campana_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_actor n_usuarios;
  v_resumen jsonb;
begin
  v_actor := n_fn_sesion(p_token);
  select jsonb_object_agg(estado, cantidad) into v_resumen
  from (
    select estado, count(*) as cantidad
    from n_registros where campana_id = p_campana_id
    group by estado
  ) t;
  return coalesce(v_resumen, '{}'::jsonb);
end;
$$;

-- ------------------------------------------------------------
-- ASIGNACIÓN AUTOMÁTICA: reparte sin duplicar, con bloqueo de fila (SKIP LOCKED)
-- Reparte p_cantidad registros a cada trabajador activo de la campaña
-- ------------------------------------------------------------
create or replace function n_fn_asignar_automatico(p_token text, p_campana_id uuid, p_cantidad int)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_actor n_usuarios;
  v_trabajador record;
  v_asignados int;
  v_total_asignado int := 0;
  v_detalle jsonb := '[]'::jsonb;
begin
  v_actor := n_fn_sesion(p_token);
  if v_actor.rol not in ('dueño','encargado') then
    raise exception 'PERMISO_DENEGADO';
  end if;

  for v_trabajador in
    select id, nombre from n_usuarios where rol = 'trabajador' and activo = true order by nombre
  loop
    with candidatos as (
      select id from n_registros
      where campana_id = p_campana_id
        and estado in ('ingresado','restante')
        and trabajador_id is null
      order by creado_en
      limit p_cantidad
      for update skip locked
    )
    update n_registros r
    set estado = 'asignado', trabajador_id = v_trabajador.id, asignado_en = now(), actualizado_en = now()
    from candidatos c
    where r.id = c.id;

    get diagnostics v_asignados = row_count;
    v_total_asignado := v_total_asignado + v_asignados;
    v_detalle := v_detalle || jsonb_build_object('trabajador', v_trabajador.nombre, 'asignados', v_asignados);
  end loop;

  insert into n_auditoria (usuario_id, rol, accion, tabla_afectada, valor_nuevo)
  values (v_actor.id, v_actor.rol, 'ASIGNAR_AUTOMATICO', 'n_registros',
          jsonb_build_object('campana_id', p_campana_id, 'total', v_total_asignado, 'detalle', v_detalle));

  return jsonb_build_object('ok', true, 'total_asignado', v_total_asignado, 'detalle', v_detalle);
end;
$$;

create or replace function n_fn_mis_registros(p_token text, p_campana_id uuid)
returns setof n_registros
language plpgsql
security definer
set search_path = public
as $$
declare
  v_actor n_usuarios;
begin
  v_actor := n_fn_sesion(p_token);
  if v_actor.rol = 'trabajador' then
    return query select * from n_registros
      where campana_id = p_campana_id and trabajador_id = v_actor.id
      order by asignado_en;
  else
    return query select * from n_registros where campana_id = p_campana_id order by asignado_en;
  end if;
end;
$$;

-- ------------------------------------------------------------
-- EQUIPOS: monitoreo (dueño/encargado)
-- ------------------------------------------------------------
create or replace function n_fn_monitor_equipos(p_token text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_actor n_usuarios;
  v_resultado jsonb;
begin
  v_actor := n_fn_sesion(p_token);
  if v_actor.rol not in ('dueño','encargado') then
    raise exception 'PERMISO_DENEGADO';
  end if;

  select jsonb_agg(jsonb_build_object(
    'codigo', e.codigo,
    'usuario', u.nombre,
    'estado', case when e.ultima_actividad > now() - interval '3 minutes' then 'conectado' else 'desconectado' end,
    'ultima_actividad', e.ultima_actividad
  ) order by e.codigo)
  into v_resultado
  from n_equipos e left join n_usuarios u on u.id = e.ultimo_usuario_id;

  return coalesce(v_resultado, '[]'::jsonb);
end;
$$;

-- ------------------------------------------------------------
-- AUDITORÍA: solo dueño
-- ------------------------------------------------------------
create or replace function n_fn_auditoria(p_token text, p_limite int default 200)
returns setof n_auditoria
language plpgsql
security definer
set search_path = public
as $$
declare
  v_actor n_usuarios;
begin
  v_actor := n_fn_sesion(p_token);
  if v_actor.rol <> 'dueño' then
    raise exception 'PERMISO_DENEGADO';
  end if;
  return query select * from n_auditoria order by creado_en desc limit p_limite;
end;
$$;

-- ============================================================
-- FIN FASE 1
-- ============================================================
