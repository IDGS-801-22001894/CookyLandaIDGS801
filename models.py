from flask_sqlalchemy import SQLAlchemy
import datetime

db = SQLAlchemy()

class Proveedor(db.Model):
    __tablename__ = 'proveedor'

    idProveedor = db.Column(db.Integer, primary_key=True)
    nombreProveedor = db.Column(db.String(150), nullable=False)
    direccion = db.Column(db.String(255), nullable=True)
    telefono = db.Column(db.String(15), nullable=True)
    correo = db.Column(db.String(100), nullable=True)
    fechaRegistro = db.Column(db.DateTime, default=datetime.datetime.now)
    tipoVendedor = db.Column(db.Enum('Principal', 'Secundario', name='tipo_vendedor_enum'), nullable=False)
    empresa = db.Column(db.String(150), nullable=False)
    estatus = db.Column(db.Enum('Activo', 'Inactivo', name='estatus_enum'), nullable=False, default='Activo')
    codigoUsuario = db.Column(db.String(255), nullable=True)

class Materia(db.Model):
    __tablename__ = 'materia'

    idProducto = db.Column(db.Integer, primary_key=True, autoincrement=True)
    nombreProducto = db.Column(db.String(200), nullable=False, unique=True)
    cantidad = db.Column(db.Numeric(10, 2), nullable=False)
    fechaCompra = db.Column(db.Date, nullable=False)

class Compra(db.Model):
    __tablename__ = 'compra'

    idCompra = db.Column(db.Integer, primary_key=True, autoincrement=True)
    fechaCompra = db.Column(db.DateTime, default=datetime.datetime.now, nullable=False)
    proveedor = db.Column(db.Integer, db.ForeignKey('proveedor.idProveedor'), nullable=False)
    total = db.Column(db.Numeric(10, 2), nullable=False)
    estatus = db.Column(db.Enum('activo', 'inactivo', name='estatus_enum'), nullable=False, default='activo')
    codigoUsuario = db.Column(db.String(255), nullable=True)

    proveedor_relacion = db.relationship('Proveedor', backref='compras')

class DetalleCompra(db.Model):
    __tablename__ = 'detalleCompra'

    idDetalle = db.Column(db.Integer, primary_key=True, autoincrement=True)
    idCompra = db.Column(db.Integer, db.ForeignKey('compra.idCompra'), nullable=False)
    nombreProducto = db.Column(db.String(200), nullable=False)
    presentacion = db.Column(db.String(100), nullable=False)
    cantidad = db.Column(db.Numeric(10, 2), nullable=False)

    compra_relacion = db.relationship('Compra', backref='detalles')

    def to_dict(self):
        return {
            "idDetalle": self.idDetalle,  # Corregido: usar idDetalle en lugar de idDetalleCompra
            "idCompra": self.idCompra,
            "nombreProducto": self.nombreProducto,
            "cantidad": float(self.cantidad),  # Convertir Decimal a float
            "presentacion": self.presentacion
        }

#ANDREA ----------------------------------------------------------------------------------

class Receta(db.Model):
    __tablename__ = 'receta'
    
    idReceta = db.Column(db.Integer, primary_key=True)
    nombreGalleta = db.Column(db.String(255), nullable=False)
    harIng = db.Column(db.String(255), default='Harina', nullable=False)
    cantHar = db.Column(db.String(150))
    manIng = db.Column(db.String(255), default='Mantequilla', nullable=False)
    cantMan = db.Column(db.String(150))
    azurIng = db.Column(db.String(255), default='Azúcar', nullable=False)
    cantAzur = db.Column(db.String(150))
    huvrIng = db.Column(db.String(255), default='Huevo', nullable=False)
    cantHuv = db.Column(db.String(150))
    vainIng = db.Column(db.String(255), default='Vainilla', nullable=False)
    cantVain = db.Column(db.String(150))
    horIng = db.Column(db.String(255), default='Polvo de Hornear', nullable=False)
    cantHor = db.Column(db.String(150))
    salIng = db.Column(db.String(255), default='Sal', nullable=False)
    cantSal = db.Column(db.String(150))
    LechIng = db.Column(db.String(255), default='Leche', nullable=False)
    cantLech = db.Column(db.String(150))
    adicional = db.Column(db.String(255), nullable=False)
    cantAdicional = db.Column(db.String(150))
    procedimiento = db.Column(db.Text, nullable=False)
    imagen = db.Column(db.Text)
    estatus = db.Column(db.Enum('Activo', 'Inactivo'), default='Activo', nullable=False)
    codigoUsuario = db.Column(db.String(255))


class Usuario(db.Model):
    __tablename__ = 'usuario'

    idUsuario = db.Column(db.Integer, primary_key=True, autoincrement=True)
    nombreCompleto = db.Column(db.String(255), nullable=False)
    apePaterno = db.Column(db.String(255), nullable=False)
    apeMaterno = db.Column(db.String(255), nullable=False)
    usuario = db.Column(db.String(255), nullable=False, unique=True)
    contrasenia = db.Column(db.String(255), nullable=False)
    correo = db.Column(db.String(255), nullable=False, unique=True)
    rol = db.Column(db.Enum('Administrador', 'Cliente', 'Vendedor', 'Cocinero'), nullable=False)
    estatus = db.Column(db.Enum('Activo', 'Inactivo'), nullable=False, default='Activo')
    codigoUsuario = db.Column(db.String(255), unique=True, nullable=True)