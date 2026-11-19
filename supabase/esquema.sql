-- =====================================================================
-- 12 Congreso Internacional del ICEA — Esquema de base de datos
-- Pegar completo en Supabase > SQL Editor > New query > Run
-- Crea: mesas, perfiles, trabajos, folios automáticos, roles
-- (autor / lider / admin), reglas de acceso y almacenamiento privado.
-- =====================================================================

-- ---------- Tablas ----------------------------------------------------

create table if not exists public.mesas (
  id          bigint generated always as identity primary key,
  nombre      text not null,
  descripcion text,
  created_at  timestamptz not null default now()
);

create table if not exists public.perfiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  correo      text,
  nombre      text not null default '',
  apellidos   text not null default '',
  institucion text not null default '',
  pais        text not null default '',
  telefono    text not null default '',
  rol         text not null default 'autor' check (rol in ('autor','lider','admin')),
  mesa_id     bigint references public.mesas(id) on delete set null,
  created_at  timestamptz not null default now()
);

create sequence if not exists public.folio_seq;

create table if not exists public.trabajos (
  id                 uuid primary key default gen_random_uuid(),
  folio              text unique,
  autor_id           uuid not null default auth.uid() references public.perfiles(id) on delete cascade,
  titulo             text not null,
  resumen            text,
  palabras_clave     text,
  coautores          text,
  mesa_id            bigint references public.mesas(id) on delete set null,
  estatus            text not null default 'recibido'
                     check (estatus in ('recibido','en_revision','aceptado','aceptado_con_cambios','rechazado')),
  observaciones      text,
  manuscrito_path    text,
  manuscrito_version int  not null default 0,
  comprobante_path   text,
  pago_estatus       text not null default 'sin_comprobante'
                     check (pago_estatus in ('sin_comprobante','por_validar','validado','rechazado')),
  carta_path         text,
  constancia_path    text,
  created_at         timestamptz not null default now(),
  updated_at         timestamptz not null default now()
);

create index if not exists trabajos_mesa_idx  on public.trabajos(mesa_id);
create index if not exists trabajos_autor_idx on public.trabajos(autor_id);

-- ---------- Funciones auxiliares (consultan sin restricciones) --------

create or replace function public.es_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from perfiles where id = auth.uid() and rol = 'admin');
$$;

create or replace function public.mi_mesa() returns bigint
language sql stable security definer set search_path = public as $$
  select mesa_id from perfiles where id = auth.uid() and rol = 'lider';
$$;

create or replace function public.lider_ve_autor(p_autor uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from trabajos t
    where t.autor_id = p_autor and t.mesa_id is not null and t.mesa_id = mi_mesa()
  );
$$;

-- ---------- Alta automática del perfil al registrarse -----------------

create or replace function public.crear_perfil() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into perfiles (id, correo, nombre, apellidos, institucion, pais, telefono)
  values (
    new.id, new.email,
    coalesce(new.raw_user_meta_data->>'nombre', ''),
    coalesce(new.raw_user_meta_data->>'apellidos', ''),
    coalesce(new.raw_user_meta_data->>'institucion', ''),
    coalesce(new.raw_user_meta_data->>'pais', ''),
    coalesce(new.raw_user_meta_data->>'telefono', '')
  )
  on conflict (id) do nothing;
  return new;
end $$;

drop trigger if exists al_registrar_usuario on auth.users;
create trigger al_registrar_usuario after insert on auth.users
  for each row execute function public.crear_perfil();

-- Un usuario puede editar sus datos, pero no su rol ni su mesa
create or replace function public.proteger_perfil() returns trigger
language plpgsql set search_path = public as $$
begin
  if auth.uid() is not null and not es_admin() then
    new.rol     := old.rol;
    new.mesa_id := old.mesa_id;
    new.correo  := old.correo;
    new.id      := old.id;
  end if;
  return new;
end $$;

drop trigger if exists proteger_perfil on public.perfiles;
create trigger proteger_perfil before update on public.perfiles
  for each row execute function public.proteger_perfil();

-- ---------- Folio y valores iniciales de cada trabajo -----------------

create or replace function public.preparar_trabajo() returns trigger
language plpgsql set search_path = public as $$
begin
  new.folio := 'ICEA12-' || lpad(nextval('public.folio_seq')::text, 4, '0');
  if auth.uid() is not null and not es_admin() then
    new.autor_id        := auth.uid();
    new.estatus         := 'recibido';
    new.observaciones   := null;
    new.carta_path      := null;
    new.constancia_path := null;
    new.pago_estatus    := case when new.comprobante_path is null
                                then 'sin_comprobante' else 'por_validar' end;
  end if;
  new.created_at := now();
  new.updated_at := now();
  return new;
end $$;

drop trigger if exists preparar_trabajo on public.trabajos;
create trigger preparar_trabajo before insert on public.trabajos
  for each row execute function public.preparar_trabajo();

-- ---------- Qué puede cambiar cada rol en un trabajo ------------------
-- Autor:  sus datos y manuscrito (mientras esté "recibido" o
--         "aceptado con cambios") y su comprobante de pago.
-- Líder:  dictamen, observaciones, carta de aceptación y constancia
--         de los trabajos de SU mesa.
-- Admin:  todo (asignar mesa, validar pago, corregir).

create or replace function public.controlar_cambios() returns trigger
language plpgsql set search_path = public as $$
declare
  cambios text[];
  permitido text[];
  es_lider boolean;
  es_autor boolean;
begin
  new.updated_at := now();
  if auth.uid() is null or es_admin() then
    return new;
  end if;

  select coalesce(array_agg(n.key), '{}') into cambios
  from jsonb_each(to_jsonb(new)) n
  where n.key <> 'updated_at' and n.value is distinct from (to_jsonb(old) -> n.key);

  es_lider := old.mesa_id is not null and old.mesa_id = mi_mesa();
  es_autor := old.autor_id = auth.uid();

  if es_lider then
    permitido := array['estatus','observaciones','carta_path','constancia_path'];
  elsif es_autor then
    permitido := array['comprobante_path','pago_estatus'];
    if old.estatus in ('recibido','aceptado_con_cambios') then
      permitido := permitido || array['titulo','resumen','palabras_clave','coautores',
                                      'manuscrito_path','manuscrito_version','estatus'];
    end if;
    if old.estatus = 'recibido' then
      permitido := permitido || array['mesa_id'];
    end if;
    -- El comprobante pasa a "por validar"; un pago ya validado no se reemplaza
    if new.comprobante_path is distinct from old.comprobante_path then
      if old.pago_estatus = 'validado' then
        raise exception 'El pago ya fue validado; no puede reemplazarse el comprobante.';
      end if;
      new.pago_estatus := 'por_validar';
      cambios := array_append(cambios, 'pago_estatus');
    elsif new.pago_estatus is distinct from old.pago_estatus then
      raise exception 'Solo el comité valida pagos.';
    end if;
    -- Nueva versión del manuscrito tras "aceptado con cambios": vuelve a revisión
    if old.estatus = 'aceptado_con_cambios'
       and new.manuscrito_path is distinct from old.manuscrito_path then
      new.estatus := 'en_revision';
      cambios := array_append(cambios, 'estatus');
    elsif new.estatus is distinct from old.estatus then
      raise exception 'El autor no puede cambiar el dictamen.';
    end if;
  else
    raise exception 'Sin permiso para modificar este trabajo.';
  end if;

  if not (cambios <@ permitido) then
    raise exception 'Cambio no permitido para tu rol: %',
      array_to_string(array(select unnest(cambios) except select unnest(permitido)), ', ');
  end if;
  return new;
end $$;

drop trigger if exists controlar_cambios on public.trabajos;
create trigger controlar_cambios before update on public.trabajos
  for each row execute function public.controlar_cambios();

-- ---------- Reglas de acceso (Row Level Security) ---------------------

alter table public.mesas    enable row level security;
alter table public.perfiles enable row level security;
alter table public.trabajos enable row level security;

drop policy if exists mesas_ver      on public.mesas;
drop policy if exists mesas_admin    on public.mesas;
create policy mesas_ver   on public.mesas for select using (true);
create policy mesas_admin on public.mesas for all using (public.es_admin()) with check (public.es_admin());

drop policy if exists perfiles_ver    on public.perfiles;
drop policy if exists perfiles_editar on public.perfiles;
create policy perfiles_ver on public.perfiles for select
  using (id = auth.uid() or public.es_admin() or public.lider_ve_autor(id));
create policy perfiles_editar on public.perfiles for update
  using (id = auth.uid() or public.es_admin())
  with check (id = auth.uid() or public.es_admin());

drop policy if exists trabajos_ver     on public.trabajos;
drop policy if exists trabajos_crear   on public.trabajos;
drop policy if exists trabajos_editar  on public.trabajos;
drop policy if exists trabajos_borrar  on public.trabajos;
create policy trabajos_ver on public.trabajos for select
  using (autor_id = auth.uid() or public.es_admin()
         or (mesa_id is not null and mesa_id = public.mi_mesa()));
create policy trabajos_crear on public.trabajos for insert
  with check (auth.uid() is not null and (autor_id = auth.uid() or public.es_admin()));
create policy trabajos_editar on public.trabajos for update
  using (autor_id = auth.uid() or public.es_admin()
         or (mesa_id is not null and mesa_id = public.mi_mesa()));
create policy trabajos_borrar on public.trabajos for delete
  using (public.es_admin());

-- ---------- Almacenamiento privado de archivos ------------------------
-- Ruta de cada archivo: <id_del_trabajo>/<tipo>-<marca>.<ext>
-- tipo = manuscrito | comprobante | carta | constancia

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('congreso', 'congreso', false, 15728640,
        array['application/pdf','application/msword',
              'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
              'image/jpeg','image/png'])
on conflict (id) do update set public = false,
  file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;

create or replace function public.archivo_permitido(p_ruta text, p_accion text) returns boolean
language plpgsql stable security definer set search_path = public as $$
declare
  partes text[] := string_to_array(p_ruta, '/');
  t trabajos%rowtype;
  archivo text;
  lider boolean;
begin
  if auth.uid() is null or array_length(partes, 1) <> 2 then
    return false;
  end if;
  if partes[1] !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then
    return false;
  end if;
  select * into t from trabajos where id = partes[1]::uuid;
  if not found then
    return false;
  end if;
  if es_admin() then
    return true;
  end if;
  archivo := partes[2];
  lider := t.mesa_id is not null and t.mesa_id = mi_mesa();

  if p_accion = 'ver' then
    return t.autor_id = auth.uid() or lider;
  end if;
  -- p_accion = 'subir'
  if t.autor_id = auth.uid() and (archivo like 'manuscrito-%' or archivo like 'comprobante-%') then
    return true;
  end if;
  if lider and (archivo like 'carta-%' or archivo like 'constancia-%') then
    return true;
  end if;
  return false;
end $$;

drop policy if exists congreso_ver    on storage.objects;
drop policy if exists congreso_subir  on storage.objects;
drop policy if exists congreso_cambiar on storage.objects;
drop policy if exists congreso_borrar on storage.objects;
create policy congreso_ver on storage.objects for select
  using (bucket_id = 'congreso' and public.archivo_permitido(name, 'ver'));
create policy congreso_subir on storage.objects for insert
  with check (bucket_id = 'congreso' and public.archivo_permitido(name, 'subir'));
create policy congreso_cambiar on storage.objects for update
  using (bucket_id = 'congreso' and public.archivo_permitido(name, 'subir'))
  with check (bucket_id = 'congreso' and public.archivo_permitido(name, 'subir'));
create policy congreso_borrar on storage.objects for delete
  using (bucket_id = 'congreso' and public.es_admin());

-- ---------- Primer administrador -------------------------------------
-- Después de crear tu cuenta en el portal, ejecuta (con tu correo):
--   update public.perfiles set rol = 'admin' where correo = 'tu-correo@uaeh.edu.mx';
