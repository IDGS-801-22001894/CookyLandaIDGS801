import base64
from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from io import open
from datetime import datetime
from flask_wtf.csrf import CSRFProtect
from flask import flash
from flask import g
from datetime import datetime
from sqlalchemy import func
from config import DevelopmentConfig
import os
import re
from decimal import Decimal


from forms import CompraForm, ProveedorForm, RecetaForm
from models import Receta, Usuario, db, Proveedor, Materia, Compra, DetalleCompra


app=Flask(__name__) 
app.config.from_object(DevelopmentConfig)
app.secret_key="esta es una clave secreta"
csrf = CSRFProtect(app)

#ANDREA ------------------------------------------------------------------------

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/catalogoReceta')
def catalogoReceta():
    recetas = Receta.query.filter_by(estatus='Activo').all() # Obtener todas las recetas de la base de datos
    return render_template('catalogoReceta.html', recetas=recetas)

@app.route('/verReceta/<int:id>')
def verReceta(id):
    receta = Receta.query.get_or_404(id)  # Obtener la receta específica o mostrar error 404
    return render_template('verReceta.html', receta=receta)

@app.route('/home')
def home():
    return render_template('index.html') 

@app.route('/registroReceta', methods=['GET', 'POST'])
def registro_receta():
    form = RecetaForm()

    recetas = Receta.query.all()  # Consulta las recetas desde la base de datos
    print("Recetas obtenidas:", recetas)  # Esto imprimirá los registros en la consola


    if request.method == 'POST':
        print("Datos del formulario recibidos:")
        print(request.form)  # Esto imprimirá los datos en la consola

        codigoUsuario = request.form.get('codigoUsuario')
        usuario = Usuario.query.filter_by(codigoUsuario=codigoUsuario, rol='Cocinero').first()

        if not usuario:
            flash("Error: No puedes registrar una receta. Código de usuario no válido.", "danger")
            return redirect(url_for('registro_receta'))

        if form.validate():
            print("Formulario validado correctamente")
            
            # En tu ruta donde procesas el formulario:
            imagen = request.files.get('imagen')
            if imagen and imagen.filename != '':  # Verifica si hay una imagen seleccionada
                try:
                    imagen_bin = imagen.read()
                    imagen_base64 = base64.b64encode(imagen_bin).decode('utf-8')  # Convertir a base64
                except Exception as e:
                    flash(f"Error al procesar la imagen: {str(e)}", "danger")
                    return render_template('registroReceta.html', form=form, recetas=recetas)
            else:
                imagen_base64 = None  # Si no se subió imagen, almacena None


            nueva_receta = Receta(
                nombreGalleta=form.nombreGalleta.data,
                harIng=form.cmbHarina.data,
                cantHar=form.cantHar.data,
                manIng=form.cmbMantequilla.data,
                cantMan=form.cantMan.data,
                azurIng=form.cmbAzucar.data,
                cantAzur=form.cantAzur.data,
                huvrIng=form.cmbHuevo.data,
                cantHuv=form.cantHuv.data,
                vainIng=form.cmbVainilla.data,
                cantVain=form.cantVain.data,
                horIng=form.cmbPolvo.data,
                cantHor=form.cantHor.data,
                salIng=form.cmbSal.data,
                cantSal=form.cantSal.data,
                LechIng=form.cmbLe.data,
                cantLech=form.cantLech.data,
                adicional=form.adicional.data,
                cantAdicional=form.cantAdicional.data,
                procedimiento=form.procedimiento.data,
                estatus=form.estatus.data,
                codigoUsuario=form.codigoUsuario.data,
                imagen=imagen_base64 
            )

            try:
                db.session.add(nueva_receta)
                db.session.commit()
                flash("Receta registrada exitosamente", "success")
                return redirect(url_for('catalogoReceta'))
            except Exception as e:
                db.session.rollback()
                print("Error al guardar en la base de datos:", str(e))
                flash("Error al registrar la receta", "danger")
        else:
            print("Errores de validación:", form.errors)

    return render_template('registroReceta.html', form=form, recetas=recetas)





@app.route('/verificar_usuario', methods=['POST'])
def verificar_usuario():
    codigoUsuario = request.form.get('codigoUsuario')
    print(f"Código de usuario recibido: {codigoUsuario}")
    usuario = Usuario.query.filter_by(codigoUsuario=codigoUsuario, rol='Cocinero').first()

    if usuario:
        print("Usuario encontrado y verificado")
        flash("Empleado verificado correctamente", "success")
        return redirect(url_for('registro_receta'))
    else:
        print("Usuario no encontrado o no tiene el rol de Cocinero")
        flash("Error: No puedes registrar una receta.", "danger")
        return redirect(url_for('registro_receta'))



@app.route('/modificar_receta/<int:idReceta>', methods=['GET', 'POST'])
def modificar_receta(idReceta):
    receta = Receta.query.get_or_404(idReceta)
    form = RecetaForm(obj=receta)

    if request.method == 'POST':
        # Manejo de la imagen
        imagen = request.files.get('imagen')
        if imagen and imagen.filename != '': 
            try:
                imagen_bin = imagen.read()
                receta.imagen = base64.b64encode(imagen_bin).decode('utf-8')  # Guarda en Base64
            except Exception as e:
                flash(f"Error al procesar la imagen: {str(e)}", "danger")
                return render_template('registroReceta2.html', form=form, receta=receta)

        # Actualiza solo los campos del formulario (excluyendo 'imagen')
        if form.validate_on_submit():
            form.populate_obj(receta)  # No sobrescribe 'imagen' porque no está en el formulario
            db.session.commit()
            flash("Receta actualizada correctamente", "success")
            return redirect(url_for('catalogoReceta'))
        else:
            flash("Corrige los errores del formulario", "danger")
            print("Errores:", form.errors)  # Debug

    return render_template('registroReceta2.html', form=form, receta=receta)



@app.route('/eliminar_receta/<int:idReceta>', methods=['POST'])
def eliminar_receta(idReceta):
    receta = Receta.query.get_or_404(idReceta)
    receta.estatus = 'Inactivo'
    db.session.commit()
    flash('Receta marcada como Inactiva', 'success')
    return redirect(url_for('registro_receta'))


#JUAN ---------------------------------------------------------------------------

def sanitize_input(value):
    """ Sanitiza la entrada del usuario eliminando caracteres peligrosos """
    if value:
        value = value.strip()  # Elimina espacios en los extremos
        value = re.sub(r'[<>]', '', value)  # Evita etiquetas HTML/JS
        return value
    return ""

@app.route('/materia', methods=['GET', 'POST'])
def materia():
    # Obtener todos los registros de la tabla Materia
    materias = Materia.query.all()
    
    # Convertir los objetos Materia a diccionarios
    materias_serializadas = [
        {
            "nombreProducto": materia.nombreProducto,
            "cantidad": float(materia.cantidad)  # Convertir Decimal a float
        }
        for materia in materias
    ]
    
    # Pasar los datos a la plantilla
    return render_template("materia.html", materias=materias_serializadas)


@app.route('/compra', methods=['GET', 'POST'])
def compra():
    form = CompraForm()
    compras = Compra.query.all()
    proveedores = Proveedor.query.all()  # Asegúrate de tener un modelo Proveedor
    proveedores_options = [f"{p.idProveedor} - {p.empresa}" for p in proveedores]
    # Convertir los detalles de compra en diccionarios
    compras_serializadas = []
    for compra in compras:
        compra_dict = {
            "idCompra": compra.idCompra,
            "fechaCompra": compra.fechaCompra.isoformat(),
            "proveedor": compra.proveedor,
            "total": float(compra.total),  # Convertir Decimal a float
            "detalles": [detalle.to_dict() for detalle in compra.detalles]
        }
        compras_serializadas.append(compra_dict)

    if 'productos' not in session:
        session['productos'] = []

    if request.method == 'POST':
        print("🔹 Datos del formulario recibidos:", request.form)

        if 'submit_agregar' in request.form:
            try:
                productos = request.form.getlist('producto[]')  # Usamos getlist para obtener todos los valores de producto[]
                cantidades = request.form.getlist('cantidad[]')  # Lo mismo con cantidad[]
                presentaciones = request.form.getlist('presentacion[]')  # Lo mismo con presentacion[]

                for producto, cantidad, presentacion in zip(productos, cantidades, presentaciones):
                    session['productos'].append({
                        'producto': producto,
                        'cantidad': Decimal(cantidad),  # Asegurarse de que cantidad es Decimal
                        'presentacion': presentacion
                    })
                session.modified = True
                print("📌 Productos en sesión:", session['productos'])
                flash("Producto agregado temporalmente", "success")
            except Exception as e:
                flash(f"Error al agregar producto: {e}", "danger")
                print(f"❌ Error al agregar producto: {e}")

            print("✅ Entrando en el bloque de confirmación")

            if not session['productos']:
                flash("No hay productos en la compra", "danger")
                return redirect(url_for('compra'))

            try:
                nueva_compra = Compra(
                    fechaCompra=datetime.now(),
                    proveedor=form.proveedor.data,
                    total=form.total.data,
                    estatus="activo",
                    codigoUsuario=form.codigoUsuario.data
                )
                db.session.add(nueva_compra)
                db.session.commit()

                print(f"🔍 Nueva compra ID: {nueva_compra.idCompra if nueva_compra.idCompra else 'No guardada'}")

                for item in session['productos']:
                    print(f"🛒 Agregando detalle: {item['producto']}, cantidad: {item['cantidad']}")

                    materia = Materia.query.filter_by(nombreProducto=item['producto']).first()
                    if materia:
                        # Actualizar cantidad de materia
                        materia.cantidad += item['cantidad']
                    else:
                        nueva_materia = Materia(
                            nombreProducto=item['producto'],
                            cantidad=item['cantidad'],
                            fechaCompra=datetime.now()
                        )
                        db.session.add(nueva_materia)

                    detalle = DetalleCompra(
                        idCompra=nueva_compra.idCompra,
                        nombreProducto=item['producto'],
                        cantidad=item['cantidad'],
                        presentacion=item['presentacion']
                    )
                    db.session.add(detalle)

                db.session.commit()
                session.pop('productos', None)

                flash("Compra realizada con éxito", "success")
                print("✅ Compra guardada en la BD con éxito")
                return redirect(url_for('compra'))

            except Exception as e:
                db.session.rollback()
                flash(f"Error al confirmar compra: {e}", "danger")
                print(f"❌ Error al confirmar compra: {e}")
                session['productos'] = []

        elif 'submit_modificar' in request.form:
            try:
                # Obtener el ID de la compra a modificar
                idCompra = request.form.get('idCompra')
                if not idCompra:
                    flash("No se ha seleccionado una compra para modificar", "danger")
                    return redirect(url_for('compra'))

                # Buscar la compra en la base de datos
                compra = Compra.query.get_or_404(idCompra)

                # Actualizar los campos de la compra
                compra.proveedor = form.proveedor.data
                compra.total = form.total.data
                compra.codigoUsuario = form.codigoUsuario.data  # Actualizar el código de usuario

                # Eliminar las cantidades antiguas de los productos asociados a la compra
                for detalle in compra.detalles:
                    materia = Materia.query.filter_by(nombreProducto=detalle.nombreProducto).first()
                    if materia:
                        materia.cantidad -= detalle.cantidad  # Restar la cantidad antigua
                        if materia.cantidad < 0:  # Evitar cantidades negativas
                            materia.cantidad = 0

                # Eliminar los detalles antiguos
                DetalleCompra.query.filter_by(idCompra=idCompra).delete()

                # Agregar los nuevos detalles y actualizar las cantidades en la tabla Materia
                productos = request.form.getlist('producto[]')
                cantidades = request.form.getlist('cantidad[]')
                presentaciones = request.form.getlist('presentacion[]')

                for producto, cantidad, presentacion in zip(productos, cantidades, presentaciones):
                    detalle = DetalleCompra(
                        idCompra=idCompra,
                        nombreProducto=producto,
                        cantidad=cantidad,
                        presentacion=presentacion
                    )
                    db.session.add(detalle)

                    # Actualizar la cantidad en la tabla Materia
                    materia = Materia.query.filter_by(nombreProducto=producto).first()
                    if materia:
                        materia.cantidad += Decimal(cantidad)  # Sumar la nueva cantidad
                    else:
                        # Si el producto no existe en la tabla Materia, crearlo
                        nueva_materia = Materia(
                            nombreProducto=producto,
                            cantidad=Decimal(cantidad),
                            fechaCompra=datetime.now()
                        )
                        db.session.add(nueva_materia)

                # Guardar los cambios en la base de datos
                db.session.commit()

                flash("Compra modificada con éxito", "success")
                print("✅ Compra modificada en la BD con éxito")
                return redirect(url_for('compra'))

            except Exception as e:
                db.session.rollback()
                flash(f"Error al modificar la compra: {e}", "danger")
                print(f"❌ Error al modificar la compra: {e}")
                return redirect(url_for('compra'))

    return render_template("compra.html", form=form, productos=session['productos'], compras=compras_serializadas, proveedores=proveedores_options)

 







@app.route('/proveedores', methods=['GET', 'POST'])
def proveedores():
    form = ProveedorForm()
    proveedores = Proveedor.query.filter_by(estatus='Activo').all()

    if request.method == 'POST':  
        if form.validate_on_submit():
            codigo_usuario = sanitize_input(request.form.get("codigoUsuario"))

            if 'submit_agregar' in request.form:
                nuevo_proveedor = Proveedor(
                    nombreProveedor=sanitize_input(form.nombre.data),
                    direccion=sanitize_input(form.direccion.data),
                    telefono=sanitize_input(form.telefono.data),
                    correo=sanitize_input(form.correo.data),
                    tipoVendedor=sanitize_input(form.vendedor.data),
                    empresa=sanitize_input(form.empresa.data),
                    codigoUsuario=codigo_usuario
                )
                db.session.add(nuevo_proveedor)
                db.session.commit()
                flash("Proveedor agregado correctamente", "success")

            elif 'submit_modificar' in request.form:
                idProveedor = request.form.get('idProveedor')
                if idProveedor:
                    proveedor = Proveedor.query.get(idProveedor)
                    if proveedor:
                        proveedor.nombreProveedor = sanitize_input(form.nombre.data)
                        proveedor.direccion = sanitize_input(form.direccion.data)
                        proveedor.telefono = sanitize_input(form.telefono.data)
                        proveedor.correo = sanitize_input(form.correo.data)
                        proveedor.tipoVendedor = sanitize_input(form.vendedor.data)
                        proveedor.empresa = sanitize_input(form.empresa.data)
                        proveedor.codigoUsuario = codigo_usuario
                        db.session.commit()
                        flash("Proveedor modificado correctamente", "success")
                    else:
                        flash("Proveedor no encontrado", "danger")

            elif 'submit_eliminar' in request.form:
                idProveedor = request.form.get('idProveedor')
                if idProveedor:
                    proveedor = Proveedor.query.get(idProveedor)
                    if proveedor:
                        proveedor.estatus = 'Inactivo'
                        db.session.commit()
                        flash("Proveedor marcado como inactivo", "success")
                    else:
                        flash("Proveedor no encontrado", "danger")

            return redirect(url_for('proveedores'))
        else:
            flash("Error en los datos. Verifique los campos.", "danger")

    return render_template("proveedor.html", form=form, proveedores=proveedores)


#levantar el servidor 
if __name__ == '__main__':
    csrf.init_app(app)
    db.init_app(app)

    with app.app_context():
        db.create_all()
    app.run()

